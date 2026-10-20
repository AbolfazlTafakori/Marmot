package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// echoOpener echoes streams; destinations on port 9 are refused.
type echoOpener struct {
	mu    sync.Mutex
	dsts  []Addr
	conns int
}

type refused struct{}

func (refused) Error() string    { return "refused" }
func (refused) SocksReply() byte { return RepConnectionRefused }

func (o *echoOpener) open(dst Addr) (io.ReadWriteCloser, error) {
	o.mu.Lock()
	o.dsts = append(o.dsts, dst)
	o.conns++
	o.mu.Unlock()
	if dst.Port == 9 {
		return nil, refused{}
	}
	if dst.Port == 10 {
		return nil, errors.New("something else")
	}
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		_, _ = io.Copy(far, far)
	}()
	return near, nil
}

func (o *echoOpener) Connect(_ context.Context, dst Addr, _ netip.AddrPort) (io.ReadWriteCloser, error) {
	return o.open(dst)
}

func (o *echoOpener) Datagram(_ context.Context, dst Addr, _ netip.AddrPort) (io.ReadWriteCloser, error) {
	return o.open(dst) // echoing framed datagrams returns them unchanged
}

func startServer(t *testing.T, o Opener) *Server {
	t.Helper()
	s, err := Listen(Config{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Opener: o, UDPIdleTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// dial performs greeting and request and returns the reply code and the
// bound address.
func dial(t *testing.T, s *Server, cmd byte, dst Addr) (net.Conn, byte, Addr) {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m != [2]byte{5, 0} {
		t.Fatalf("method reply %x %v", m, err)
	}
	_, _ = c.Write(appendAddr([]byte{5, cmd, 0}, dst))
	var h [3]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		t.Fatal(err)
	}
	bound, err := readAddr(c)
	if err != nil {
		t.Fatal(err)
	}
	return c, h[1], bound
}

func TestConnect(t *testing.T) {
	o := &echoOpener{}
	s := startServer(t, o)
	c, rep, bound := dial(t, s, cmdConnect, Addr{Host: "example.com", Port: 443})
	defer c.Close()
	if rep != RepSucceeded || !bound.IP.IsLoopback() {
		t.Fatalf("reply %d bound %+v", rep, bound)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	got := make([]byte, 18)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("echo %q %v", got, err)
	}
	if o.dsts[0] != (Addr{Host: "example.com", Port: 443}) {
		t.Fatalf("destination %+v", o.dsts[0])
	}
}

func TestReplies(t *testing.T) {
	s := startServer(t, &echoOpener{})
	cases := []struct {
		cmd  byte
		dst  Addr
		want byte
	}{
		{cmdConnect, Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 9}, RepConnectionRefused},
		{cmdConnect, Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 10}, RepGeneralFailure},
		{cmdBind, Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 80}, RepCommandNotSupported},
	}
	for _, c := range cases {
		conn, rep, _ := dial(t, s, c.cmd, c.dst)
		conn.Close()
		if rep != c.want {
			t.Errorf("cmd %d dst %v: reply %d want %d", c.cmd, c.dst, rep, c.want)
		}
	}
	// An unknown address type gets "address type not supported".
	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0, 5, 1, 0, 9})
	r := make([]byte, 4) // method reply (2 bytes), then VER | REP
	_, _ = io.ReadFull(conn, r)
	if r[0] != 5 || r[1] != 0 || r[3] != RepAddrNotSupported {
		t.Fatalf("bad atyp reply %x", r)
	}
}

func TestNoAcceptableMethod(t *testing.T) {
	s := startServer(t, &echoOpener{})
	c, _ := net.Dial("tcp", s.Addr().String())
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 2})
	m := make([]byte, 2)
	_, _ = io.ReadFull(c, m)
	if !bytes.Equal(m, []byte{5, 0xFF}) {
		t.Fatalf("reply %x", m)
	}
	if _, err := c.Read(m); err == nil {
		t.Fatal("connection kept open after method refusal")
	}
}

func TestUDPAssociate(t *testing.T) {
	o := &echoOpener{}
	s := startServer(t, o)
	ctl, rep, bound := dial(t, s, cmdUDPAssociate, Addr{IP: netip.IPv4Unspecified()})
	if rep != RepSucceeded || bound.Port == 0 {
		t.Fatalf("reply %d bound %+v", rep, bound)
	}
	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bound.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
	dns := Addr{IP: netip.MustParseAddr("192.0.2.53"), Port: 53}
	buf := make([]byte, 2048)
	for _, q := range []string{"query-1", "query-2"} {
		if _, err := uc.Write(appendUDP(nil, dns, []byte(q))); err != nil {
			t.Fatal(err)
		}
		n, err := uc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		src, data, err := parseUDP(buf[:n])
		if err != nil || src != dns || string(data) != q {
			t.Fatalf("answer %+v %q %v", src, data, err)
		}
	}
	o.mu.Lock()
	streams := o.conns
	o.mu.Unlock()
	if streams != 1 {
		t.Fatalf("one destination should use one stream, got %d", streams)
	}
	// Closing the control connection ends the association.
	ctl.Close()
	time.Sleep(200 * time.Millisecond)
	_, _ = uc.Write(appendUDP(nil, dns, []byte("late")))
	_ = uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := uc.Read(buf); err == nil {
		t.Fatal("association outlived its control connection")
	}
}

func TestListenValidates(t *testing.T) {
	if _, err := Listen(Config{Listen: netip.MustParseAddrPort("127.0.0.1:0")}); err == nil {
		t.Fatal("missing opener accepted")
	}
}
