package forwarder

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/proxyproto"
)

var client = netip.MustParseAddrPort("203.0.113.50:51515")

// serve runs f.Serve on one end of a pipe and returns the peer's end.
func serve(t *testing.T, f *Forwarder, h frame.StreamHeader) net.Conn {
	t.Helper()
	peer, local := net.Pipe()
	go f.Serve(context.Background(), local, h)
	t.Cleanup(func() { _ = peer.Close() })
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	return peer
}

func reply(t *testing.T, c net.Conn) byte {
	t.Helper()
	var r [1]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		t.Fatal(err)
	}
	return r[0]
}

// proxyEchoServer accepts one connection, expects a PROXY v2 header when
// wantProxy is set, reports it, and echoes.
func proxyEchoServer(t *testing.T, wantProxy bool) (uint16, <-chan proxyproto.Header) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	hdrs := make(chan proxyproto.Header, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if wantProxy {
			h, err := proxyproto.ReadHeader(c)
			if err != nil {
				t.Errorf("proxy header: %v", err)
				return
			}
			hdrs <- h
		}
		_, _ = io.Copy(c, c)
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port), hdrs
}

func newForwarder(t *testing.T, p Policy) *Forwarder {
	t.Helper()
	if p.TargetHost == "" {
		p.TargetHost = "127.0.0.1"
	}
	f, err := New(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func tcpHeader(port uint16) frame.StreamHeader {
	return frame.StreamHeader{Proto: core.ProtoTCP, Class: core.ClassTunneled, TargetPort: port, Client: client}
}

func TestTCPWithProxyV2(t *testing.T) {
	port, hdrs := proxyEchoServer(t, true)
	f := newForwarder(t, Policy{ProxyV2: true})
	c := serve(t, f, tcpHeader(port))
	if r := reply(t, c); r != frame.ReplyOK {
		t.Fatalf("reply %d", r)
	}
	if _, err := c.Write([]byte("vless bytes")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("vless bytes"))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "vless bytes" {
		t.Fatalf("echo %q %v", got, err)
	}
	h := <-hdrs
	if h.Src != client || h.Dst.Port() != port {
		t.Fatalf("proxy header %+v", h)
	}
}

func TestTCPProxyV2PortFilter(t *testing.T) {
	port, _ := proxyEchoServer(t, false)
	f := newForwarder(t, Policy{ProxyV2: true, ProxyV2Ports: map[uint16]bool{1: true}})
	c := serve(t, f, tcpHeader(port))
	if r := reply(t, c); r != frame.ReplyOK {
		t.Fatalf("reply %d", r)
	}
	_, _ = c.Write([]byte("x"))
	got := make([]byte, 1)
	if _, err := io.ReadFull(c, got); err != nil || got[0] != 'x' {
		t.Fatalf("echo %q %v (a PROXY header was sent to an unlisted port?)", got, err)
	}
}

func TestRefusals(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()

	f := newForwarder(t, Policy{DeniedPorts: map[uint16]bool{22: true}})
	routed := tcpHeader(443)
	routed.Route = []core.NodeID{"relay-1"}
	udp := tcpHeader(443)
	udp.Proto = core.ProtoUDP

	cases := []struct {
		name string
		h    frame.StreamHeader
		want byte
	}{
		{"closed port", tcpHeader(closedPort), frame.ReplyRefused},
		{"protected port", tcpHeader(22), frame.ReplyDenied},
		{"relay route", routed, frame.ReplyDenied},
		{"udp disabled", udp, frame.ReplyDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if r := reply(t, serve(t, f, c.h)); r != c.want {
				t.Fatalf("reply %d, want %d", r, c.want)
			}
		})
	}
	if s := f.Stats(); s.Refused != 4 || s.Streams != 4 {
		t.Fatalf("stats %+v", s)
	}
}

func TestUDPFlow(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(buf[:n], from)
		}
	}()
	f := newForwarder(t, Policy{AllowUDP: true, UDPIdleTimeout: 300 * time.Millisecond})
	h := tcpHeader(uint16(uc.LocalAddr().(*net.UDPAddr).Port))
	h.Proto = core.ProtoUDP
	c := serve(t, f, h)
	if r := reply(t, c); r != frame.ReplyOK {
		t.Fatalf("reply %d", r)
	}
	scratch := make([]byte, 2+frame.MaxDatagram)
	buf := make([]byte, frame.MaxDatagram)
	for _, msg := range []string{"quic initial", "second"} {
		if err := frame.WriteDatagram(c, scratch, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		n, err := frame.ReadDatagram(c, buf)
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("echo %q %v", buf[:n], err)
		}
	}
	// The flow ends by itself once idle.
	if _, err := frame.ReadDatagram(c, buf); err == nil {
		t.Fatal("idle flow was not closed")
	}
}

func TestPolicyValidation(t *testing.T) {
	if _, err := New(Policy{}, nil); err == nil {
		t.Fatal("empty target host accepted")
	}
	f := newForwarder(t, Policy{})
	if err := f.SetPolicy(Policy{TargetHost: "127.0.0.1", AllowUDP: true}); err == nil {
		t.Fatal("udp without idle timeout accepted")
	}
}
