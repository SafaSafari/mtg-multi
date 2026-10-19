package middle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
)

func seq(from, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(from + i)
	}

	return out
}

// Vectors are produced by get_middleproxy_aes_key_and_iv from
// alexbers/mtprotoproxy with the same inputs.
func TestDeriveMatchesReference(t *testing.T) {
	base := keyMaterial{
		nonceSrv: seq(0, 16),
		nonceClt: seq(16, 16),
		cltTS:    []byte{1, 2, 3, 4},
		myPort:   40000,
		secret:   seq(0, 128),
	}

	tests := []struct {
		name    string
		myIP    string
		tgIP    string
		tgPort  uint16
		purpose string
		key, iv string
	}{
		{"v4 client", "62.60.217.179", "149.154.175.50", 8888, "CLIENT",
			"e994acdcac62a4f3936af04f509f89475a78491efc72b49b646447e8ae870ff9", "86742b3e3e3761291e8650d2c7b62687"},
		{"v4 server", "62.60.217.179", "149.154.175.50", 8888, "SERVER",
			"e1dc62e81a5289fbf5f4b523d0e7d075805142289fbb6e1284e0665e9aed6ad6", "990a307721fa919548992dbcc9cf5033"},
		{"v6 client", "2a01:e5c0:58ed::2", "2001:b28:f23d:f001::d", 80, "CLIENT",
			"b604f70a9c623207f1250f52dc52cc45bf872232a48b311dd2405625440f3a1c", "35a1026b81e190d0a90b39c541234690"},
		{"v6 server", "2a01:e5c0:58ed::2", "2001:b28:f23d:f001::d", 80, "SERVER",
			"b9b4143ce92e7e6976ad58723736d074ce45bc280edc55ee339187913863a607", "63b52436ce47f115f5dc2dabf3c979ef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := base
			k.myIP = netip.MustParseAddr(tt.myIP)
			k.tgIP = netip.MustParseAddr(tt.tgIP)
			k.tgPort = tt.tgPort

			key, iv := k.derive(tt.purpose)
			if hex.EncodeToString(key) != tt.key || hex.EncodeToString(iv) != tt.iv {
				t.Fatalf("got key=%x iv=%x", key, iv)
			}
		})
	}
}

func TestParseProxyConfig(t *testing.T) {
	body := []byte(`# force_probability 10 10
default 2;
proxy_for 1 149.154.175.50:8888;
proxy_for -1 149.154.175.50:8888;
proxy_for 2 149.154.161.144:8888;
proxy_for 2 149.154.161.145:8888;
proxy_for 203 91.105.192.100:443;
garbage line
`)

	list, err := parseProxyConfig(body)
	if err != nil {
		t.Fatal(err)
	}

	if list.defaultDC != 2 || len(list.get(2)) != 2 || len(list.get(-1)) != 1 || len(list.get(203)) != 1 {
		t.Fatalf("unexpected list: %+v", list)
	}

	// Unknown DC falls back to the default one.
	if got := list.get(42); len(got) != 2 {
		t.Fatalf("fallback: %v", got)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	block, _ := aes.NewCipher(seq(0, 32))
	iv := seq(32, 16)

	var buf bytes.Buffer

	w := &frameWriter{w: &buf, mode: cipher.NewCBCEncrypter(block, iv)}
	r := &frameReader{r: newCBCReader(&buf, cipher.NewCBCDecrypter(block, iv))}

	for _, size := range []int{4, 8, 12, 16, 100, 4096, 65536} {
		payload := seq(size, size)
		if err := w.Write(payload); err != nil {
			t.Fatal(err)
		}

		if buf.Len()%cbcBlockSize != 0 {
			t.Fatalf("frame is not block aligned: %d", buf.Len())
		}

		got, err := r.Read()
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}

		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: payload mismatch", size)
		}
	}
}

// fakeMiddleProxy is the server side of the RPC protocol, enough to check
// the handshake and the RPC_PROXY_REQ layout.
type fakeMiddleProxy struct {
	t      *testing.T
	secret []byte
	reqs   chan []byte
}

func (f *fakeMiddleProxy) serve(conn net.Conn) {
	defer conn.Close()

	r := &frameReader{r: conn, seqNo: startSeqNo}
	w := &frameWriter{w: conn, seqNo: startSeqNo}

	req, err := r.Read()
	if err != nil {
		f.t.Errorf("server: read nonce: %v", err)
		return
	}

	nonceSrv := seq(100, 16)
	if err := w.Write(slices.Concat(rpcNonce[:], req[4:8], cryptoAES[:], req[12:16], nonceSrv)); err != nil {
		f.t.Errorf("server: write nonce: %v", err)
		return
	}

	// The server sees the client as remote: same key material as the client.
	client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	server := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	keys := keyMaterial{
		nonceSrv: nonceSrv,
		nonceClt: req[16:32],
		cltTS:    req[12:16],
		myIP:     client.Addr().Unmap(),
		myPort:   client.Port(),
		tgIP:     server.Addr().Unmap(),
		tgPort:   server.Port(),
		secret:   f.secret,
	}

	decKey, decIV := keys.derive("CLIENT")
	encKey, encIV := keys.derive("SERVER")
	decBlock, _ := aes.NewCipher(decKey)
	encBlock, _ := aes.NewCipher(encKey)

	r.r = newCBCReader(conn, cipher.NewCBCDecrypter(decBlock, decIV))
	w.mode = cipher.NewCBCEncrypter(encBlock, encIV)

	hs, err := r.Read()
	if err != nil || [4]byte(hs[:4]) != rpcHandshake {
		f.t.Errorf("server: bad handshake: %v", err)
		return
	}

	if err := w.Write(slices.Concat(rpcHandshake[:], rpcFlags[:], processID, processID)); err != nil {
		return
	}

	for {
		msg, err := r.Read()
		if err != nil {
			return
		}

		f.reqs <- msg

		// Echo the client packet back as RPC_PROXY_ANS.
		connID := msg[8:16]
		packet := msg[len(msg)-8:]

		if err := w.Write(slices.Concat(rpcProxyAns[:], []byte{0, 0, 0, 0}, connID, packet)); err != nil {
			return
		}
	}
}

func TestSessionWithAdTag(t *testing.T) {
	secret := seq(7, 128)
	adTag := seq(200, AdTagLength)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fake := &fakeMiddleProxy{t: t, secret: secret, reqs: make(chan []byte, 1)}

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			fake.serve(conn)
		}
	}()

	tgConn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	session, err := Handshake(essentials.WrapNetConn(tgConn), secret, Endpoint{})
	if err != nil {
		t.Fatal(err)
	}

	// The proxy side of a client connection: a TCP pair so RemoteAddr is real.
	clientLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	userConn, err := net.Dial("tcp4", clientLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer userConn.Close()

	proxySide, err := clientLn.Accept()
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)

	go func() {
		done <- session.Relay(essentials.WrapNetConn(proxySide), proxySide.RemoteAddr(), adTag)
	}()

	// Padded intermediate packet: 8 bytes of data + 3 bytes of padding, with
	// the quick ack bit set.
	data := []byte("abcdefgh")
	pkt := make([]byte, 4, 4+len(data)+3)
	binary.LittleEndian.PutUint32(pkt, uint32(len(data)+3)|quickAckBit)
	pkt = append(append(pkt, data...), 1, 2, 3)

	if _, err := userConn.Write(pkt); err != nil {
		t.Fatal(err)
	}

	var req []byte
	select {
	case req = <-fake.reqs:
	case <-time.After(5 * time.Second):
		t.Fatal("no RPC_PROXY_REQ")
	}

	flags := binary.LittleEndian.Uint32(req[4:8])
	want := uint32(clientTransportFlags | flagHasAdTag | flagQuickAck)

	if [4]byte(req[:4]) != rpcProxyReq || flags != want {
		t.Fatalf("bad header: type=%x flags=%x want %x", req[:4], flags, want)
	}

	userAddr := userConn.LocalAddr().(*net.TCPAddr).AddrPort()
	if got := [20]byte(req[16:36]); got != ipPort(userAddr) {
		t.Fatalf("client ip:port = %x, want %x", got, ipPort(userAddr))
	}

	ext := req[56:]
	if [4]byte(ext[:4]) != extraSize || [4]byte(ext[4:8]) != proxyTag || ext[8] != AdTagLength ||
		!bytes.Equal(ext[9:25], adTag) || !bytes.Equal(ext[28:], data) {
		t.Fatalf("bad extra / payload: %x", ext)
	}

	// Echoed answer comes back as a padded intermediate packet.
	var lenBuf [4]byte
	if _, err := io.ReadFull(userConn, lenBuf[:]); err != nil {
		t.Fatal(err)
	}

	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n < uint32(len(data)) || n >= uint32(len(data)+maxClientPad) {
		t.Fatalf("bad answer length %d", n)
	}

	ans := make([]byte, n)
	if _, err := io.ReadFull(userConn, ans); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ans[:len(data)], data) {
		t.Fatalf("answer = %q", ans)
	}

	userConn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relay: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop")
	}
}

func TestHandshakeRejectsMissingSecret(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	if _, err := Handshake(essentials.WrapNetConn(a), nil, Endpoint{}); err == nil {
		t.Fatal("expected error")
	}
}
