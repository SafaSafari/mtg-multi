package middle

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/dolonet/mtg-multi/essentials"
)

var (
	rpcProxyReq  = [4]byte{0xee, 0xf1, 0xce, 0x36}
	rpcProxyAns  = [4]byte{0x0d, 0xda, 0x03, 0x44}
	rpcSimpleAck = [4]byte{0x9b, 0x40, 0xac, 0x3b}
	rpcCloseExt  = [4]byte{0xa2, 0x34, 0xb6, 0x5e}

	extraSize = [4]byte{0x18, 0x00, 0x00, 0x00}
	proxyTag  = [4]byte{0xae, 0x26, 0x1e, 0xdb}

	errClosedByTelegram = errors.New("connection closed by middle proxy")
)

// RPC_PROXY_REQ flags.
const (
	flagNotEncrypted = 0x2
	flagHasAdTag     = 0x8
	flagMagic        = 0x1000
	flagExtMode2     = 0x20000
	flagPad          = 0x8000000
	flagIntermediate = 0x20000000
	flagQuickAck     = 0x80000000

	// mtg accepts only the padded intermediate ("secure", 0xdddddddd)
	// transport, so these flags are constant for every client.
	clientTransportFlags = flagMagic | flagExtMode2 | flagIntermediate | flagPad

	AdTagLength = 16

	quickAckBit     = 0x80000000
	maxClientPacket = 1 << 24
	maxClientPad    = 4
)

// Relay pipes a client connection (already de-obfuscated, padded
// intermediate transport) through the middle-proxy session. It returns when
// either side is closed; both connections are closed on return.
func (s *Session) Relay(client essentials.Conn, clientAddr net.Addr, adTag []byte) error {
	if len(adTag) != 0 && len(adTag) != AdTagLength {
		return fmt.Errorf("ad tag must be %d bytes, got %d", AdTagLength, len(adTag))
	}

	clientAP, err := addrPort(clientAddr)
	if err != nil {
		clientAP = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}

	var connID [8]byte
	if _, err := rand.Read(connID[:]); err != nil {
		return err //nolint: wrapcheck
	}

	header := s.proxyReqHeader(connID, ipPort(clientAP), adTag)

	var (
		once     sync.Once
		firstErr error
		wg       sync.WaitGroup
	)

	stop := func(err error) {
		once.Do(func() {
			firstErr = err
			client.Close() //nolint: errcheck
			s.conn.Close() //nolint: errcheck
		})
	}

	wg.Go(func() { stop(s.clientToTelegram(client, header)) })
	wg.Go(func() { stop(s.telegramToClient(client)) })
	wg.Wait()

	if errors.Is(firstErr, io.EOF) || errors.Is(firstErr, errClosedByTelegram) {
		return nil
	}

	return firstErr
}

// Close closes the underlying middle-proxy connection.
func (s *Session) Close() error {
	return s.conn.Close() //nolint: wrapcheck
}

func (s *Session) proxyReqHeader(connID [8]byte, clientIPPort [20]byte, adTag []byte) []byte {
	header := slices.Concat(
		rpcProxyReq[:],
		[]byte{0, 0, 0, 0}, // flags, filled per packet
		connID[:],
		clientIPPort[:],
		s.ourIPPort[:],
	)

	if len(adTag) == AdTagLength {
		header = slices.Concat(header, extraSize[:], proxyTag[:], []byte{AdTagLength}, adTag, []byte{0, 0, 0})
	}

	return header
}

func (s *Session) clientToTelegram(client io.Reader, header []byte) error {
	var lenBuf [4]byte

	hasAdTag := len(header) > 4+4+8+20+20 //nolint: mnd

	for {
		if _, err := io.ReadFull(client, lenBuf[:]); err != nil {
			return err //nolint: wrapcheck
		}

		length := binary.LittleEndian.Uint32(lenBuf[:])
		quickAck := length&quickAckBit != 0
		length &^= quickAckBit

		if length > maxClientPacket {
			return fmt.Errorf("client packet is too large: %d", length)
		}

		msg := make([]byte, len(header)+int(length))
		copy(msg, header)

		packet := msg[len(header):]
		if _, err := io.ReadFull(client, packet); err != nil {
			return err //nolint: wrapcheck
		}

		// Padded intermediate adds 0..3 random bytes at the end.
		packet = packet[:len(packet)-len(packet)%4]
		msg = msg[:len(header)+len(packet)]

		flags := uint32(clientTransportFlags)
		if hasAdTag {
			flags |= flagHasAdTag
		}

		if quickAck {
			flags |= flagQuickAck
		}

		if len(packet) >= 8 && [8]byte(packet[:8]) == [8]byte{} {
			flags |= flagNotEncrypted
		}

		binary.LittleEndian.PutUint32(msg[4:8], flags)

		if err := s.w.Write(msg); err != nil {
			return err
		}
	}
}

func (s *Session) telegramToClient(client io.Writer) error {
	var padding [maxClientPad]byte

	for {
		ans, err := s.r.Read()
		if err != nil {
			return err
		}

		if len(ans) < 4 { //nolint: mnd
			continue
		}

		switch [4]byte(ans[:4]) {
		case rpcProxyAns:
			// [type:4][flags:4][conn_id:8][data]
			if len(ans) < 16 { //nolint: mnd
				continue
			}

			data := ans[16:]

			var padLen [1]byte
			if _, err := rand.Read(padLen[:]); err != nil {
				return err //nolint: wrapcheck
			}

			pad := int(padLen[0]) % maxClientPad
			if _, err := rand.Read(padding[:pad]); err != nil {
				return err //nolint: wrapcheck
			}

			out := make([]byte, 4+len(data)+pad)
			binary.LittleEndian.PutUint32(out, uint32(len(data)+pad)) //nolint: gosec
			copy(out[4:], data)
			copy(out[4+len(data):], padding[:pad])

			if _, err := client.Write(out); err != nil {
				return err //nolint: wrapcheck
			}
		case rpcSimpleAck:
			// [type:4][conn_id:8][confirm:4]
			if len(ans) < 16 { //nolint: mnd
				continue
			}

			if _, err := client.Write(ans[12:16]); err != nil {
				return err //nolint: wrapcheck
			}
		case rpcCloseExt:
			return errClosedByTelegram
		}
	}
}
