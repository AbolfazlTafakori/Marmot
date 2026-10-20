package transport_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"marmot/internal/transport"
	_ "marmot/internal/transport/tcp"
	_ "marmot/internal/transport/tls"
)

func TestRegistry(t *testing.T) {
	if err := transport.Check(); err != nil {
		t.Fatal(err)
	}
	names := transport.Names()
	if len(names) != 2 || names[0] != "tcp" || names[1] != "tls" {
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
	msg := []byte("marmot says hello")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo %q", got)
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
