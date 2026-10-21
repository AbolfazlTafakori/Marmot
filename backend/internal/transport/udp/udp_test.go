package udp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"marmot/internal/transport"
)

// proxy forwards datagrams between one client and a server, dropping the
// first dropFirst datagrams of each direction and then every dropEvery-th
// (0 = none).
type proxy struct {
	sock      *net.UDPConn
	server    netip.AddrPort
	client    atomic.Pointer[netip.AddrPort]
	dropFirst int
	dropEvery int
	mu        sync.Mutex
	n         [2]int
}

func newProxy(t *testing.T, server netip.AddrPort, dropFirst, dropEvery int) *proxy {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{sock: pc.(*net.UDPConn), server: server, dropFirst: dropFirst, dropEvery: dropEvery}
	t.Cleanup(func() { _ = p.sock.Close() })
	go p.run()
	return p
}

func (p *proxy) addr() netip.AddrPort { return netip.MustParseAddrPort(p.sock.LocalAddr().String()) }

func (p *proxy) drop(dir int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n[dir]++
	n := p.n[dir]
	return n <= p.dropFirst || (p.dropEvery > 0 && n%p.dropEvery == 0)
}

func (p *proxy) run() {
	buf := make([]byte, 65536)
	for {
		n, from, err := p.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from == p.server {
			if c := p.client.Load(); c != nil && !p.drop(1) {
				_, _ = p.sock.WriteToUDPAddrPort(buf[:n], *c)
			}
			continue
		}
		p.client.Store(&from)
		if !p.drop(0) {
			_, _ = p.sock.WriteToUDPAddrPort(buf[:n], p.server)
		}
	}
}

func listen(t *testing.T) transport.Listener {
	t.Helper()
	l, err := Transport{}.Listen(context.Background(), transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// exchange runs a request/reply over the handshake stream, as Noise does.
func exchange(t *testing.T, l transport.Listener, dialTo netip.AddrPort) (client, server transport.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Transport{}.Dial(ctx, transport.Endpoint{Addr: dialTo}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	req := bytes.Repeat([]byte("q"), 300)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_ = s.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(req))
	if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, req) {
		t.Fatalf("server read %d bytes: %v", len(got), err)
	}
	if _, err := s.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	_ = c.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(5 * time.Second))
	rep := make([]byte, 5)
	if _, err := io.ReadFull(c, rep); err != nil || string(rep) != "reply" {
		t.Fatalf("client read %q: %v", rep, err)
	}
	return c, s
}

func TestHandshakeAndDatagrams(t *testing.T) {
	l := listen(t)
	c, s := exchange(t, l, netip.MustParseAddrPort(l.Addr().String()))
	cd, sd := c.(transport.Datagrammer), s.(transport.Datagrammer)
	if !cd.DatagramsEnabled() || cd.MaxDatagramSize() != maxDatagram-1 {
		t.Fatal("datagram settings")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := bytes.Repeat([]byte{9}, cd.MaxDatagramSize())
	if err := cd.SendDatagram(msg); err != nil {
		t.Fatal(err)
	}
	if d, err := sd.ReceiveDatagram(ctx); err != nil || !bytes.Equal(d, msg) {
		t.Fatalf("server got %d bytes: %v", len(d), err)
	}
	if err := sd.SendDatagram([]byte("back")); err != nil {
		t.Fatal(err)
	}
	if d, err := cd.ReceiveDatagram(ctx); err != nil || string(d) != "back" {
		t.Fatalf("client got %q: %v", d, err)
	}
	if err := cd.SendDatagram(make([]byte, maxDatagram)); err == nil {
		t.Fatal("oversized datagram accepted")
	}
	// Close reaches the peer.
	_ = c.Close()
	if _, err := sd.ReceiveDatagram(ctx); err == nil {
		t.Fatal("peer still open after close")
	}
}

// The first datagrams of both directions are lost: the handshake must
// still complete by resending.
func TestHandshakeSurvivesLoss(t *testing.T) {
	l := listen(t)
	p := newProxy(t, netip.MustParseAddrPort(l.Addr().String()), 2, 0)
	start := time.Now()
	exchange(t, l, p.addr())
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("handshake took %v", d)
	}
}

func TestListenerCloseAndKind(t *testing.T) {
	if (Transport{}).Name() != Name || (Transport{}).Kind() != transport.Datagram {
		t.Fatal("name or kind")
	}
	l := listen(t)
	errc := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		errc <- err
	}()
	_ = l.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("accept after close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still blocked")
	}
}

func TestReadDeadline(t *testing.T) {
	l := listen(t)
	c, err := Transport{}.Dial(context.Background(), transport.Endpoint{Addr: netip.MustParseAddrPort(l.Addr().String())}, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read past deadline: %v", err)
	}
}
