package middle

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// Sequence numbers start at -2: the nonce exchange uses -2, the
	// handshake -1 and data frames 0, 1, 2...
	startSeqNo = -2

	frameHeaderLen  = 8 // length + seq_no
	frameTrailerLen = 4 // crc32
	minFrameLen     = frameHeaderLen + frameTrailerLen
	maxFrameLen     = 1 << 24

	cbcBlockSize = 16
)

// The 4-byte filler that pads frames to the CBC block size. A frame never
// has length 4, so readers just skip it.
var paddingFiller = [4]byte{0x04, 0x00, 0x00, 0x00}

var errBadFrame = errors.New("bad rpc frame")

// cbcReader decrypts a stream encrypted with AES-CBC. Reads from the
// underlying reader are always whole blocks.
type cbcReader struct {
	r     io.Reader
	mode  cipher.BlockMode
	plain []byte
	buf   []byte
}

func newCBCReader(r io.Reader, mode cipher.BlockMode) *cbcReader {
	return &cbcReader{r: r, mode: mode, buf: make([]byte, 0, 64*1024)} //nolint: mnd
}

func (c *cbcReader) Read(p []byte) (int, error) {
	if len(c.plain) == 0 {
		// Read at least one block, keep only whole blocks.
		buf := c.buf[:cap(c.buf)]
		n, err := io.ReadAtLeast(c.r, buf, cbcBlockSize)
		if err != nil {
			return 0, err //nolint: wrapcheck
		}

		if rest := n % cbcBlockSize; rest != 0 {
			if _, err := io.ReadFull(c.r, buf[n:n+cbcBlockSize-rest]); err != nil {
				return 0, err //nolint: wrapcheck
			}

			n += cbcBlockSize - rest
		}

		c.mode.CryptBlocks(buf[:n], buf[:n])
		c.plain = buf[:n]
	}

	n := copy(p, c.plain)
	c.plain = c.plain[n:]

	return n, nil
}

// frameReader reads MTProto RPC frames:
// [len:4][seq_no:4][payload][crc32:4], with optional 4-byte fillers between.
type frameReader struct {
	r     io.Reader
	seqNo int32
}

func (f *frameReader) Read() ([]byte, error) {
	var header [frameHeaderLen]byte

	for {
		if _, err := io.ReadFull(f.r, header[:4]); err != nil {
			return nil, err //nolint: wrapcheck
		}

		if [4]byte(header[:4]) != paddingFiller {
			break
		}
	}

	msgLen := binary.LittleEndian.Uint32(header[:4])
	if msgLen < minFrameLen || msgLen > maxFrameLen || msgLen%4 != 0 {
		return nil, fmt.Errorf("%w: length %d", errBadFrame, msgLen)
	}

	if _, err := io.ReadFull(f.r, header[4:]); err != nil {
		return nil, err //nolint: wrapcheck
	}

	if seqNo := int32(binary.LittleEndian.Uint32(header[4:])); seqNo != f.seqNo { //nolint: gosec
		return nil, fmt.Errorf("%w: seq_no %d, expected %d", errBadFrame, seqNo, f.seqNo)
	}

	f.seqNo++

	body := make([]byte, msgLen-frameHeaderLen)
	if _, err := io.ReadFull(f.r, body); err != nil {
		return nil, err //nolint: wrapcheck
	}

	payload := body[:len(body)-frameTrailerLen]
	checksum := binary.LittleEndian.Uint32(body[len(body)-frameTrailerLen:])

	crc := crc32.NewIEEE()
	crc.Write(header[:])
	crc.Write(payload)

	if crc.Sum32() != checksum {
		return nil, fmt.Errorf("%w: crc32 mismatch", errBadFrame)
	}

	return payload, nil
}

// frameWriter writes MTProto RPC frames. If mode is set, frames are padded
// to the block size and encrypted with AES-CBC.
type frameWriter struct {
	w     io.Writer
	mode  cipher.BlockMode
	seqNo int32
}

func (f *frameWriter) Write(payload []byte) error {
	msgLen := minFrameLen + len(payload)
	total := msgLen

	if f.mode != nil {
		total += (cbcBlockSize - msgLen%cbcBlockSize) % cbcBlockSize
	}

	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:], uint32(msgLen)) //nolint: gosec
	binary.LittleEndian.PutUint32(buf[4:], uint32(f.seqNo))
	copy(buf[frameHeaderLen:], payload)
	binary.LittleEndian.PutUint32(buf[msgLen-frameTrailerLen:], crc32.ChecksumIEEE(buf[:msgLen-frameTrailerLen]))

	for i := msgLen; i < total; i += len(paddingFiller) {
		copy(buf[i:], paddingFiller[:])
	}

	f.seqNo++

	if f.mode != nil {
		f.mode.CryptBlocks(buf, buf)
	}

	_, err := f.w.Write(buf)

	return err //nolint: wrapcheck
}
