package middle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint: gosec
	"crypto/rand"
	"crypto/sha1" //nolint: gosec
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
)

var (
	rpcNonce     = [4]byte{0xaa, 0x87, 0xcb, 0x7a}
	rpcHandshake = [4]byte{0xf5, 0xee, 0x82, 0x76}
	cryptoAES    = [4]byte{0x01, 0x00, 0x00, 0x00}
	rpcFlags     = [4]byte{}
	processID    = []byte("IPIPPRPDTIME")

	ErrHandshake = errors.New("middle proxy handshake failed")
)

const (
	nonceLen           = 16
	nonceAnswerLen     = 32
	handshakeAnswerLen = 32
)

// Endpoint is what we (the proxy) look like to the middle proxy. Public IPs
// override local socket addresses when the proxy runs behind NAT.
type Endpoint struct {
	PublicIPv4 netip.Addr
	PublicIPv6 netip.Addr
}

// Session is an established, encrypted RPC connection to a middle proxy.
type Session struct {
	conn essentials.Conn
	r    *frameReader
	w    *frameWriter

	// Our ip:port as sent in RPC_PROXY_REQ (IPv6 or IPv4-mapped + LE port).
	ourIPPort [20]byte
}

// Handshake performs RPC_NONCE and RPC_HANDSHAKE over a fresh TCP
// connection to a middle proxy.
func Handshake(conn essentials.Conn, secret []byte, ep Endpoint) (*Session, error) {
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("%w: proxy secret is not loaded", ErrHandshake)
	}

	local, err := addrPort(conn.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("%w: local address: %w", ErrHandshake, err)
	}

	remote, err := addrPort(conn.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("%w: remote address: %w", ErrHandshake, err)
	}

	myIP := local.Addr()

	switch {
	case remote.Addr().Is4() && ep.PublicIPv4.IsValid():
		myIP = ep.PublicIPv4
	case remote.Addr().Is6() && ep.PublicIPv6.IsValid():
		myIP = ep.PublicIPv6
	}

	if myIP.Is4() != remote.Addr().Is4() {
		return nil, fmt.Errorf("%w: address family mismatch %s / %s", ErrHandshake, myIP, remote.Addr())
	}

	keySelector := [4]byte(secret[:4])

	var cryptoTS [4]byte
	binary.LittleEndian.PutUint32(cryptoTS[:], uint32(time.Now().Unix())) //nolint: gosec

	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	w := &frameWriter{w: conn, seqNo: startSeqNo}
	r := &frameReader{r: conn, seqNo: startSeqNo}

	req := slices.Concat(rpcNonce[:], keySelector[:], cryptoAES[:], cryptoTS[:], nonce[:])
	if err := w.Write(req); err != nil {
		return nil, fmt.Errorf("%w: cannot send nonce: %w", ErrHandshake, err)
	}

	ans, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read nonce: %w", ErrHandshake, err)
	}

	if len(ans) != nonceAnswerLen ||
		[4]byte(ans[0:4]) != rpcNonce ||
		[4]byte(ans[4:8]) != keySelector ||
		[4]byte(ans[8:12]) != cryptoAES {
		return nil, fmt.Errorf("%w: bad nonce answer", ErrHandshake)
	}

	keys := keyMaterial{
		nonceSrv: ans[16:32],
		nonceClt: nonce[:],
		cltTS:    cryptoTS[:],
		myIP:     myIP,
		myPort:   local.Port(),
		tgIP:     remote.Addr(),
		tgPort:   remote.Port(),
		secret:   secret,
	}

	encKey, encIV := keys.derive("CLIENT")
	decKey, decIV := keys.derive("SERVER")

	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	w.mode = cipher.NewCBCEncrypter(encBlock, encIV)
	r.r = newCBCReader(conn, cipher.NewCBCDecrypter(decBlock, decIV))

	if err := w.Write(slices.Concat(rpcHandshake[:], rpcFlags[:], processID, processID)); err != nil {
		return nil, fmt.Errorf("%w: cannot send handshake: %w", ErrHandshake, err)
	}

	ans, err = r.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read handshake: %w", ErrHandshake, err)
	}

	if len(ans) != handshakeAnswerLen ||
		[4]byte(ans[0:4]) != rpcHandshake ||
		!bytes.Equal(ans[20:32], processID) {
		return nil, fmt.Errorf("%w: bad handshake answer", ErrHandshake)
	}

	return &Session{
		conn:      conn,
		r:         r,
		w:         w,
		ourIPPort: ipPort(netip.AddrPortFrom(myIP, local.Port())),
	}, nil
}

type keyMaterial struct {
	nonceSrv []byte
	nonceClt []byte
	cltTS    []byte
	myIP     netip.Addr
	myPort   uint16
	tgIP     netip.Addr
	tgPort   uint16
	secret   []byte
}

// derive builds the AES-256-CBC key and IV for one direction. purpose is
// "CLIENT" for our writes and "SERVER" for our reads.
func (k keyMaterial) derive(purpose string) ([]byte, []byte) {
	var (
		srvIPv4 = make([]byte, 4) //nolint: mnd
		cltIPv4 = make([]byte, 4) //nolint: mnd
		port    [2]byte
		s       bytes.Buffer
	)

	if k.tgIP.Is4() {
		tg, my := k.tgIP.As4(), k.myIP.As4()
		srvIPv4 = slices.Clone(tg[:])
		cltIPv4 = slices.Clone(my[:])
		slices.Reverse(srvIPv4)
		slices.Reverse(cltIPv4)
	}

	s.Write(k.nonceSrv)
	s.Write(k.nonceClt)
	s.Write(k.cltTS)
	s.Write(srvIPv4)
	binary.LittleEndian.PutUint16(port[:], k.myPort)
	s.Write(port[:])
	s.WriteString(purpose)
	s.Write(cltIPv4)
	binary.LittleEndian.PutUint16(port[:], k.tgPort)
	s.Write(port[:])
	s.Write(k.secret)
	s.Write(k.nonceSrv)

	if !k.tgIP.Is4() {
		my, tg := k.myIP.As16(), k.tgIP.As16()
		s.Write(my[:])
		s.Write(tg[:])
	}

	s.Write(k.nonceClt)

	data := s.Bytes()
	md5Sum := md5.Sum(data[1:]) //nolint: gosec
	sha1Sum := sha1.Sum(data)   //nolint: gosec
	iv := md5.Sum(data[2:])     //nolint: gosec

	return slices.Concat(md5Sum[:12], sha1Sum[:]), iv[:]
}

func addrPort(addr net.Addr) (netip.AddrPort, error) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		ap := tcp.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}

	if addr == nil {
		return netip.AddrPort{}, errors.New("no address")
	}

	// Wrapped connections may expose a non-TCP net.Addr; parse its text.
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("middle proxy needs a direct TCP connection, got %q: %w", addr.String(), err)
	}

	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// ipPort encodes an address as 16-byte IPv6 (IPv4 is ::ffff:a.b.c.d) plus a
// 4-byte little-endian port.
func ipPort(ap netip.AddrPort) [20]byte {
	var out [20]byte

	ip := ap.Addr().Unmap()
	if ip.Is4() {
		ip = netip.AddrFrom16(ip.As16())
	}

	ip16 := ip.As16()
	copy(out[:16], ip16[:])
	binary.LittleEndian.PutUint32(out[16:], uint32(ap.Port()))

	return out
}
