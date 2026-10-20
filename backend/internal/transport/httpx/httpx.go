// Package httpx holds what the HTTP-based transports (ws, grpc) share: the
// TCP or TLS socket under them, the endpoint options that pick it, and a
// listener that turns accepted HTTP requests into transport connections.
package httpx

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"marmot/internal/transport"
	"marmot/internal/transport/tcp"
	mtls "marmot/internal/transport/tls"
)

// HeaderTimeout bounds the TLS handshake and request headers of an
// accepted connection, so a silent client cannot hold a goroutine.
const HeaderTimeout = 10 * time.Second

// UseTLS reads the "tls" option (default true).
func UseTLS(opts map[string]any) (bool, error) { return transport.BoolOption(opts, "tls", true) }

// Dial opens the socket an HTTP transport runs on: TCP, then uTLS with
// alpn unless the "tls" option is false.
func Dial(ctx context.Context, ep transport.Endpoint, local netip.Addr, alpn []string) (net.Conn, error) {
	useTLS, err := UseTLS(ep.Options)
	if err != nil {
		return nil, err
	}
	raw, err := tcp.DialTCP(ctx, ep.Addr, local)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return raw, nil
	}
	uc, err := mtls.Client(ctx, raw, ep.Options, alpn)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake %s: %w", ep.Addr, err)
	}
	return uc, nil
}

// Host returns the authority to send: the "host" option, else "sni", else
// the dialed address.
func Host(ep transport.Endpoint) (string, error) {
	host, err := transport.StringOption(ep.Options, "host", "")
	if err != nil || host != "" {
		return host, err
	}
	sni, err := transport.StringOption(ep.Options, "sni", "")
	if err != nil || sni != "" {
		return sni, err
	}
	return ep.Addr.String(), nil
}

// OnceDialer hands out one already-connected socket to an HTTP client.
type OnceDialer struct {
	mu   sync.Mutex
	conn net.Conn
}

// NewOnceDialer wraps c.
func NewOnceDialer(c net.Conn) *OnceDialer { return &OnceDialer{conn: c} }

// DialContext returns the socket the first time and fails afterwards, so a
// transport never opens a second connection behind Marmot's back.
func (d *OnceDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.conn
	d.conn = nil
	if c == nil {
		return nil, errors.New("httpx: connection already used")
	}
	return c, nil
}

// Conn gives a tunnel the socket's real addresses and a SetDeadline.
type Conn struct {
	io.ReadWriteCloser
	Local, Remote net.Addr
	Deadline      func(t time.Time) error // nil = not supported
}

// LocalAddr implements transport.Conn.
func (c *Conn) LocalAddr() net.Addr { return c.Local }

// RemoteAddr implements transport.Conn.
func (c *Conn) RemoteAddr() net.Addr { return c.Remote }

// SetDeadline bounds the session handshake on the tunnel.
func (c *Conn) SetDeadline(t time.Time) error {
	if c.Deadline == nil {
		return nil
	}
	return c.Deadline(t)
}

// Listener accepts tunnels from HTTP requests. A handler hands each tunnel
// to Deliver; Accept returns them.
type Listener struct {
	srv   *http.Server
	tl    *net.TCPListener
	addr  net.Addr
	conns chan transport.Conn
	done  chan struct{}
	once  sync.Once
}

// Listen serves h on a TCP listener at addr, under TLS offering
// nextProtos unless the "tls" option is false. h2 enables HTTP/2 (with
// TLS, or cleartext prior knowledge without it).
func Listen(ctx context.Context, cfg transport.ListenConfig, h http.Handler, nextProtos []string, h2 bool) (*Listener, error) {
	useTLS, err := UseTLS(cfg.Options)
	if err != nil {
		return nil, err
	}
	var conf *stdtls.Config
	if useTLS {
		if conf, err = mtls.ServerConfig(cfg.Options, nextProtos); err != nil {
			return nil, err
		}
	}
	tl, err := tcp.ListenTCP(ctx, cfg.Addr)
	if err != nil {
		return nil, err
	}
	l := &Listener{tl: tl, addr: tl.Addr(), conns: make(chan transport.Conn), done: make(chan struct{})}
	l.srv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: HeaderTimeout,
		IdleTimeout:       time.Minute,
		TLSConfig:         conf,
		ErrorLog:          log.New(io.Discard, "", 0), // probes and scanners are not news
	}
	var protos http.Protocols
	switch {
	case h2 && useTLS:
		protos.SetHTTP2(true)
	case h2:
		protos.SetUnencryptedHTTP2(true)
	default:
		protos.SetHTTP1(true)
	}
	l.srv.Protocols = &protos
	go func() {
		if useTLS {
			_ = l.srv.ServeTLS(tl, "", "")
		} else {
			_ = l.srv.Serve(tl)
		}
	}()
	return l, nil
}

// Deliver hands an accepted tunnel to Accept. It returns false when the
// listener is closed; the caller then closes c.
func (l *Listener) Deliver(ctx context.Context, c transport.Conn) bool {
	select {
	case l.conns <- c:
		return true
	case <-l.done:
		return false
	case <-ctx.Done():
		return false
	}
}

// Done is closed when the listener closes.
func (l *Listener) Done() <-chan struct{} { return l.done }

// Accept implements transport.Listener.
func (l *Listener) Accept() (transport.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting. Tunnels already handed out stay open, as with
// the tcp transport; they belong to their sessions. Serving goroutines end
// with their connections.
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.tl.Close()
}

// Addr implements transport.Listener.
func (l *Listener) Addr() net.Addr { return l.addr }
