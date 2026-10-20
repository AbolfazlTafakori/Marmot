package transport_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"marmot/internal/transport"
	_ "marmot/internal/transport/grpc"
	_ "marmot/internal/transport/tcp"
	_ "marmot/internal/transport/tls"
	_ "marmot/internal/transport/ws"
)

func TestRegistry(t *testing.T) {
	if err := transport.Check(); err != nil {
		t.Fatal(err)
	}
	names := transport.Names()
	if strings.Join(names, ",") != "grpc,tcp,tls,ws" {
		t.Fatalf("names = %v", names)
	}
	if _, err := transport.Get("carrier-pigeon"); !errors.Is(err, transport.ErrUnknown) {
		t.Fatalf("err = %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
	}{
		{"tcp", nil},
		{"tls", map[string]any{"sni": "example.com"}},
		{"tls", map[string]any{"fingerprint": "firefox"}},
		{"tls", map[string]any{"fingerprint": "go"}},
		{"ws", map[string]any{"path": "/cdn-cgi/ws", "sni": "example.com"}},
		{"ws", map[string]any{"tls": false}},
		{"ws", map[string]any{"fingerprint": "firefox", "host": "front.example.com"}},
		{"grpc", map[string]any{"service": "pkg.Svc", "sni": "example.com"}},
		{"grpc", map[string]any{"tls": false}},
		{"grpc", map[string]any{"fingerprint": "safari"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { roundTrip(t, c.name, c.opts) })
	}
}

func roundTrip(t *testing.T, name string, opts map[string]any) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr, err := transport.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tr.Listen(ctx, transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0"), Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	addr := netip.MustParseAddrPort(l.Addr().String())
	c, err := tr.Dial(ctx, transport.Endpoint{Addr: addr, Options: opts}, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, msg := range [][]byte{[]byte("marmot says hello"), bytes.Repeat([]byte("0123456789abcdef"), 20000)} {
		go func() { _, _ = c.Write(msg) }()
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("echo of %d bytes differs", len(msg))
		}
	}
	if _, err := netip.ParseAddrPort(c.LocalAddr().String()); err != nil {
		t.Fatalf("local address %q is not the socket's: %v", c.LocalAddr(), err)
	}
	if d, ok := c.(interface{ SetDeadline(time.Time) error }); !ok {
		t.Fatal("no SetDeadline: the session handshake would be unbounded")
	} else if err := d.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestBadOptions(t *testing.T) {
	tr, _ := transport.Get("tls")
	ctx := context.Background()
	ep := transport.Endpoint{Addr: netip.MustParseAddrPort("127.0.0.1:1"), Options: map[string]any{"fingerprint": "netscape"}}
	if _, err := tr.Dial(ctx, ep, netip.Addr{}); err == nil {
		t.Fatal("unknown fingerprint accepted")
	}
	ep.Options = map[string]any{"sni": 5}
	if _, err := tr.Dial(ctx, ep, netip.Addr{}); err == nil {
		t.Fatal("non-string sni accepted")
	}
	lc := transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0"), Options: map[string]any{"cert_file": "x"}}
	if _, err := tr.Listen(ctx, lc); err == nil {
		t.Fatal("cert_file without key_file accepted")
	}
}

// Requests that are not the tunnel get what a plain web or gRPC server
// would answer, and the listener keeps working.
func TestHTTPTransportsLookOrdinary(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"ws", "grpc"} {
		tr, _ := transport.Get(name)
		l, err := tr.Listen(ctx, transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0"),
			Options: map[string]any{"path": "/tunnel"}})
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // test against a self-signed certificate
			ForceAttemptHTTP2: true,
		}}
		resp, err := client.Get("https://" + l.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: GET / = %d, want 404", name, resp.StatusCode)
		}
		_ = l.Close()
		if _, err := l.Accept(); err == nil {
			t.Errorf("%s: Accept after Close succeeded", name)
		}
	}
}

func TestHTTPTransportBadOptions(t *testing.T) {
	ctx := context.Background()
	lc := func(opts map[string]any) transport.ListenConfig {
		return transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0"), Options: opts}
	}
	ws, _ := transport.Get("ws")
	if _, err := ws.Listen(ctx, lc(map[string]any{"path": "ws"})); err == nil {
		t.Error("ws path without / accepted")
	}
	g, _ := transport.Get("grpc")
	if _, err := g.Listen(ctx, lc(map[string]any{"service": "a/b"})); err == nil {
		t.Error("grpc service with / accepted")
	}
	if _, err := g.Listen(ctx, lc(map[string]any{"tls": "yes"})); err == nil {
		t.Error("non-boolean tls accepted")
	}
}
