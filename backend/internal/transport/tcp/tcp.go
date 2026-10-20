// Package tcp is the plain TCP transport.
package tcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"marmot/internal/transport"
)

// Name is the registered transport name.
const Name = "tcp"

// keepAlive is short so a dead path is noticed by the kernel too, not only
// by the session's PING probing.
const keepAlive = 15 * time.Second

func init() { transport.Register(Transport{}) }

// Transport dials and listens on raw TCP.
type Transport struct{}

// Name implements transport.Transport.
func (Transport) Name() string { return Name }

// Kind implements transport.Transport.
func (Transport) Kind() transport.Kind { return transport.Stream }

// Dial implements transport.Transport.
func (Transport) Dial(ctx context.Context, ep transport.Endpoint, local netip.Addr) (transport.Conn, error) {
	c, err := DialTCP(ctx, ep.Addr, local)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// DialTCP opens a TCP connection with Marmot's socket settings. Other
// transports that run over TCP use it as their base.
func DialTCP(ctx context.Context, addr netip.AddrPort, local netip.Addr) (*net.TCPConn, error) {
	d := net.Dialer{KeepAlive: keepAlive}
	if local.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: local.AsSlice()}
	}
	c, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}
	tc := c.(*net.TCPConn)
	// Records are already sized; Nagle would only add latency.
	_ = tc.SetNoDelay(true)
	return tc, nil
}

// Listen implements transport.Transport.
func (Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	l, err := ListenTCP(ctx, cfg.Addr)
	if err != nil {
		return nil, err
	}
	return listener{l}, nil
}

// ListenTCP opens a TCP listener with Marmot's socket settings.
func ListenTCP(ctx context.Context, addr netip.AddrPort) (*net.TCPListener, error) {
	lc := net.ListenConfig{KeepAlive: keepAlive}
	l, err := lc.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	return l.(*net.TCPListener), nil
}

type listener struct{ *net.TCPListener }

func (l listener) Accept() (transport.Conn, error) {
	c, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = c.SetNoDelay(true)
	return c, nil
}
