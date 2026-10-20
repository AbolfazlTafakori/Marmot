// Package ws is the WebSocket transport: a tunnel inside one binary
// WebSocket, over TLS (uTLS on the client) or plain TCP. It passes through
// CDNs and HTTP reverse proxies that forward WebSockets.
//
// As with tls, TLS is camouflage; the Noise handshake inside authenticates
// the peer.
package ws

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/coder/websocket"

	"marmot/internal/transport"
	"marmot/internal/transport/httpx"
)

// Name is the registered transport name.
const Name = "ws"

// maxMessage bounds one WebSocket message. Records are far smaller; the
// limit only stops an unauthenticated client from streaming forever.
const maxMessage = 1 << 20

// alpn is offered and required: WebSocket upgrades need HTTP/1.1.
var alpn = []string{"http/1.1"}

func init() { transport.Register(Transport{}) }

// Transport is WebSocket over TLS or TCP.
//
// Endpoint options: path (default "/"), host (Host header; default sni or
// the address), tls (default true), sni, fingerprint (as for tls).
// Listen options: path, tls, cert_file, key_file, sni (as for tls).
type Transport struct{}

// Name implements transport.Transport.
func (Transport) Name() string { return Name }

// Kind implements transport.Transport.
func (Transport) Kind() transport.Kind { return transport.Stream }

func pathOption(opts map[string]any) (string, error) {
	p, err := transport.StringOption(opts, "path", "/")
	if err != nil {
		return "", err
	}
	if p == "" || p[0] != '/' {
		return "", fmt.Errorf("ws: path %q must start with /", p)
	}
	return p, nil
}

// Dial implements transport.Transport.
func (Transport) Dial(ctx context.Context, ep transport.Endpoint, local netip.Addr) (transport.Conn, error) {
	path, err := pathOption(ep.Options)
	if err != nil {
		return nil, err
	}
	host, err := httpx.Host(ep)
	if err != nil {
		return nil, err
	}
	useTLS, err := httpx.UseTLS(ep.Options)
	if err != nil {
		return nil, err
	}
	sock, err := httpx.Dial(ctx, ep, local, alpn)
	if err != nil {
		return nil, err
	}
	d := httpx.NewOnceDialer(sock)
	u := url.URL{Scheme: "http", Host: ep.Addr.String(), Path: path}
	if useTLS {
		u.Scheme = "https"
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext:    d.DialContext,
		DialTLSContext: d.DialContext, // already past the TLS handshake
	}}
	c, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: client, Host: host})
	if err != nil {
		_ = sock.Close()
		return nil, fmt.Errorf("ws dial %s: %w", ep.Addr, err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	c.SetReadLimit(maxMessage)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	return &httpx.Conn{ReadWriteCloser: nc, Local: sock.LocalAddr(), Remote: sock.RemoteAddr(), Deadline: nc.SetDeadline}, nil
}

// Listen implements transport.Transport.
func (Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	path, err := pathOption(cfg.Options)
	if err != nil {
		return nil, err
	}
	h := &handler{path: path}
	l, err := httpx.Listen(ctx, cfg, h, alpn, false)
	if err != nil {
		return nil, err
	}
	h.l = l
	return l, nil
}

type handler struct {
	path string
	l    *httpx.Listener
}

// ServeHTTP upgrades requests for the tunnel path; everything else gets
// the 404 any web server would give.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != h.path {
		http.NotFound(w, r)
		return
	}
	// Not a browser: the origin check protects cookies we do not have.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return // Accept has answered the request
	}
	c.SetReadLimit(maxMessage)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	conn := &httpx.Conn{ReadWriteCloser: nc, Local: nc.LocalAddr(), Remote: nc.RemoteAddr(), Deadline: nc.SetDeadline}
	if !h.l.Deliver(r.Context(), conn) {
		_ = nc.Close()
	}
}
