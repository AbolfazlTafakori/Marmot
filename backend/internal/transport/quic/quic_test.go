package quic

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"marmot/internal/transport"
)

// pair dials a fresh listener with the given endpoint options and returns
// both ends.
func pair(t *testing.T, opts map[string]any) (client, server transport.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := Transport{}.Listen(ctx, transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan transport.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	addr := netip.MustParseAddrPort(l.Addr().String())
	c, err := Transport{}.Dial(ctx, transport.Endpoint{Addr: addr, Options: opts}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	// The server sees the connection once the first stream carries data,
	// as the Noise handshake does.
	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-accepted:
		if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
		return c, s
	case <-ctx.Done():
		t.Fatal("no connection accepted")
		return nil, nil
	}
}

func TestDatagramsBothWays(t *testing.T) {
	c, s := pair(t, nil)
	cd, sd := c.(transport.Datagrammer), s.(transport.Datagrammer)
	if !cd.DatagramsEnabled() || !sd.DatagramsEnabled() {
		t.Fatal("datagrams not negotiated")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := bytes.Repeat([]byte{7}, cd.MaxDatagramSize())
	// Datagrams may be lost even on loopback; send until one arrives.
	got := make(chan []byte, 1)
	go func() {
		d, err := sd.ReceiveDatagram(ctx)
		if err == nil {
			got <- d
		}
	}()
	for {
		if err := cd.SendDatagram(msg); err != nil {
			t.Fatalf("send at the advertised maximum: %v", err)
		}
		select {
		case d := <-got:
			if !bytes.Equal(d, msg) {
				t.Fatal("datagram changed in transit")
			}
			return
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("no datagram arrived")
		}
	}
}

func TestDatagramsOffAgreesOnBothEnds(t *testing.T) {
	c, s := pair(t, map[string]any{"datagrams": false})
	if c.(transport.Datagrammer).DatagramsEnabled() || s.(transport.Datagrammer).DatagramsEnabled() {
		t.Fatal("one end thinks datagrams are on")
	}
}

func TestCloseEndsPeer(t *testing.T) {
	c, s := pair(t, nil)
	_ = c.Close()
	_ = s.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded after the peer closed")
	}
}

func TestBadOptions(t *testing.T) {
	ctx := context.Background()
	ep := transport.Endpoint{Addr: netip.MustParseAddrPort("127.0.0.1:1"), Options: map[string]any{"datagrams": "yes"}}
	if _, err := (Transport{}).Dial(ctx, ep, netip.Addr{}); err == nil {
		t.Fatal("non-boolean datagrams accepted")
	}
	ep.Options = map[string]any{"alpn": 3}
	if _, err := (Transport{}).Dial(ctx, ep, netip.Addr{}); err == nil {
		t.Fatal("non-string alpn accepted")
	}
}

func TestNameKindAndLocalAddress(t *testing.T) {
	if (Transport{}).Name() != Name || (Transport{}).Kind() != transport.Datagram {
		t.Fatal("name or kind")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := Transport{}.Listen(ctx, transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if s, err := l.Accept(); err == nil {
			_, _ = io.Copy(s, s)
		}
	}()
	local := netip.MustParseAddr("127.0.0.1")
	c, err := Transport{}.Dial(ctx, transport.Endpoint{Addr: netip.MustParseAddrPort(l.Addr().String())}, local)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := netip.MustParseAddrPort(c.LocalAddr().String()).Addr(); got != local {
		t.Fatalf("local address %v, want %v", got, local)
	}
	if c.RemoteAddr().String() != l.Addr().String() {
		t.Fatalf("remote %v, listener %v", c.RemoteAddr(), l.Addr())
	}
	// A datagram over the advertised maximum is refused, not truncated.
	if err := c.(transport.Datagrammer).SendDatagram(make([]byte, 64<<10)); err == nil {
		t.Fatal("oversized datagram accepted")
	}
}

func TestListenerCloseEndsAccept(t *testing.T) {
	l, err := Transport{}.Listen(context.Background(), transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		errc <- err
	}()
	_ = l.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Accept returned a connection after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still blocked after Close")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestListenBadOptions(t *testing.T) {
	ctx := context.Background()
	addr := netip.MustParseAddrPort("127.0.0.1:0")
	if _, err := (Transport{}).Listen(ctx, transport.ListenConfig{Addr: addr, Options: map[string]any{"alpn": 1}}); err == nil {
		t.Fatal("non-string alpn accepted")
	}
	if _, err := (Transport{}).Listen(ctx, transport.ListenConfig{Addr: addr, Options: map[string]any{"cert_file": "x"}}); err == nil {
		t.Fatal("cert_file without key_file accepted")
	}
	ep := transport.Endpoint{Addr: netip.MustParseAddrPort("127.0.0.1:1"), Options: map[string]any{"sni": 5}}
	if _, err := (Transport{}).Dial(ctx, ep, netip.Addr{}); err == nil {
		t.Fatal("non-string sni accepted")
	}
}

func TestDialNobodyListening(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddrPort(pc.LocalAddr().String())
	_ = pc.Close()
	if _, err := (Transport{}).Dial(ctx, transport.Endpoint{Addr: addr}, netip.Addr{}); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
}
