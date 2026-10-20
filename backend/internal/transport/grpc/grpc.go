// Package grpc is the gRPC transport: a tunnel inside one bidirectional
// gRPC call, over HTTP/2 with TLS (uTLS on the client) or cleartext
// HTTP/2. On the wire it is gRPC: POST /<service>/Tun with content-type
// application/grpc, length-prefixed messages and grpc-status trailers, so
// gRPC-aware CDNs and proxies carry it. It does not use the gRPC library;
// a tunnel needs only the framing.
//
// As with tls, TLS is camouflage; the Noise handshake inside authenticates
// the peer.
package grpc

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/transport"
	"marmot/internal/transport/httpx"
)

// Name is the registered transport name.
const Name = "grpc"

// maxMessage bounds one gRPC message, as gRPC's own default receive limit
// does. Records are far smaller.
const maxMessage = 4 << 20

// prefixLen is the gRPC message prefix: compressed flag and length.
const prefixLen = 5

// userAgent is what common gRPC clients send.
const userAgent = "grpc-go/1.71.0"

var alpn = []string{"h2"}

func init() { transport.Register(Transport{}) }

// Transport is gRPC over HTTP/2.
//
// Endpoint options: service (default "marmot.Tunnel"; the call is
// /<service>/Tun), host (:authority; default sni or the address), tls
// (default true), sni, fingerprint (as for tls).
// Listen options: service, tls, cert_file, key_file, sni (as for tls).
type Transport struct{}

// Name implements transport.Transport.
func (Transport) Name() string { return Name }

// Kind implements transport.Transport.
func (Transport) Kind() transport.Kind { return transport.Stream }

func methodPath(opts map[string]any) (string, error) {
	svc, err := transport.StringOption(opts, "service", "marmot.Tunnel")
	if err != nil {
		return "", err
	}
	if svc == "" || strings.ContainsAny(svc, "/ ?#") {
		return "", fmt.Errorf("grpc: bad service name %q", svc)
	}
	return "/" + svc + "/Tun", nil
}

// Dial implements transport.Transport.
func (Transport) Dial(ctx context.Context, ep transport.Endpoint, local netip.Addr) (transport.Conn, error) {
	path, err := methodPath(ep.Options)
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
	if cs, ok := sock.(interface{ ConnectionState() tls.ConnectionState }); ok && useTLS {
		if p := cs.ConnectionState().NegotiatedProtocol; p != "h2" {
			_ = sock.Close()
			return nil, fmt.Errorf("grpc dial %s: server chose %q, not h2", ep.Addr, p)
		}
	}
	c, err := dialCall(ctx, sock, useTLS, ep.Addr.String(), host, path)
	if err != nil {
		_ = sock.Close()
		return nil, fmt.Errorf("grpc dial %s: %w", ep.Addr, err)
	}
	return c, nil
}

func dialCall(ctx context.Context, sock net.Conn, useTLS bool, addr, host, path string) (transport.Conn, error) {
	// The handshake deadline of ctx covers the HTTP/2 preface and the
	// response headers; afterwards the call lives as long as the session.
	if d, ok := ctx.Deadline(); ok {
		_ = sock.SetDeadline(d)
		defer func() { _ = sock.SetDeadline(time.Time{}) }()
	}
	d := httpx.NewOnceDialer(sock)
	tr := &http.Transport{
		DialContext: d.DialContext,
		// The socket is already past the uTLS handshake; tlsState tells
		// net/http that h2 was negotiated.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return tlsState{c}, nil
		},
		HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second},
	}
	var protos http.Protocols
	scheme := "http"
	if useTLS {
		scheme = "https"
		protos.SetHTTP2(true)
	} else {
		protos.SetUnencryptedHTTP2(true)
	}
	tr.Protocols = &protos
	cc, err := tr.NewClientConn(ctx, scheme, addr)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, scheme+"://"+host+path, pr)
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	req.Host = host // :authority; the URL host may not be dialable
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("User-Agent", userAgent)
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := cc.RoundTrip(req) //nolint:bodyclose // the body is the tunnel; conn closes it
		done <- result{resp, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		_ = cc.Close()
		_ = pw.Close()
		if r = <-done; r.err == nil {
			_ = r.resp.Body.Close()
		}
		return nil, ctx.Err()
	}
	if r.err != nil {
		_ = cc.Close()
		_ = pw.Close()
		return nil, r.err
	}
	if r.resp.StatusCode != http.StatusOK || !isGRPC(r.resp.Header.Get("Content-Type")) {
		_ = r.resp.Body.Close()
		_ = cc.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("unexpected response %s", r.resp.Status)
	}
	body := r.resp.Body
	c := &conn{
		r: body, w: pw, flush: func() error { return nil },
		local: sock.LocalAddr(), remote: sock.RemoteAddr(),
		deadline: sock.SetDeadline,
	}
	c.closeFn = func() error {
		err := pw.Close()
		_ = body.Close()
		_ = cc.Close()
		_ = sock.Close()
		return err
	}
	return c, nil
}

// tlsState reports the uTLS connection's negotiated protocol in the
// crypto/tls form net/http looks for.
type tlsState struct{ net.Conn }

func (c tlsState) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{HandshakeComplete: true, NegotiatedProtocol: "h2"}
}

func isGRPC(ct string) bool {
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+")
}

// Listen implements transport.Transport.
func (Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	path, err := methodPath(cfg.Options)
	if err != nil {
		return nil, err
	}
	h := &handler{path: path}
	l, err := httpx.Listen(ctx, cfg, h, alpn, true)
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

// ServeHTTP runs one tunnel per call of the tunnel method. Anything else
// gets what a gRPC server or web server would answer.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 || !isGRPC(r.Header.Get("Content-Type")) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	if r.Method != http.MethodPost || r.URL.Path != h.path {
		w.Header().Set("Grpc-Status", "12") // UNIMPLEMENTED, trailers-only
		w.Header().Set("Grpc-Message", "unknown method")
		w.WriteHeader(http.StatusOK)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}
	closed := make(chan struct{})
	var once sync.Once
	c := &conn{
		r: r.Body, w: w, flush: rc.Flush,
		local: localAddr(r), remote: remoteAddr(r),
		deadline: func(t time.Time) error {
			return errors.Join(rc.SetReadDeadline(t), rc.SetWriteDeadline(t))
		},
		closeFn: func() error {
			once.Do(func() { close(closed) })
			return nil
		},
	}
	if !h.l.Deliver(r.Context(), c) {
		return
	}
	select {
	case <-closed:
	case <-r.Context().Done():
	case <-h.l.Done():
	}
	// No more writes may reach w once the handler returns: refuse new
	// ones, abort one blocked on flow control (a blackholed peer grants no
	// window), and wait for it to leave.
	c.closed.Store(true)
	_ = rc.SetWriteDeadline(time.Unix(1, 0))
	c.mu.Lock()
	//nolint:staticcheck,gocritic // empty critical section: waiting for an in-flight Write
	c.mu.Unlock()
	w.Header().Set("Grpc-Status", "0")
	// The response writer is gone once we return: a session still in its
	// handshake must not set deadlines on it.
	c.dmu.Lock()
	c.ended = true
	c.dmu.Unlock()
}

func localAddr(r *http.Request) net.Addr {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return a
	}
	return &net.TCPAddr{}
}

func remoteAddr(r *http.Request) net.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	return &net.TCPAddr{}
}

// conn carries a byte stream as gRPC messages: each Write is one message,
// and Read returns message payloads back to back.
type conn struct {
	r    io.Reader
	left int // payload bytes of the current message not yet read
	hdr  [prefixLen]byte
	rmu  sync.Mutex

	mu      sync.Mutex // serialises writes; Close never takes it
	w       io.Writer
	flush   func() error
	closed  atomic.Bool
	closeFn func() error // unblocks a Write that is stuck

	local, remote net.Addr
	deadline      func(t time.Time) error
	dmu           sync.Mutex // guards ended against SetDeadline
	ended         bool       // server side: the handler has returned
}

func (c *conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for c.left == 0 {
		if _, err := io.ReadFull(c.r, c.hdr[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if c.hdr[0] != 0 {
			return 0, errors.New("grpc: compressed message")
		}
		n := binary.BigEndian.Uint32(c.hdr[1:])
		if n > maxMessage {
			return 0, fmt.Errorf("grpc: message of %d bytes", n)
		}
		c.left = int(n)
	}
	if len(b) > c.left {
		b = b[:c.left]
	}
	n, err := c.r.Read(b)
	c.left -= n
	if err == io.EOF && c.left > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (c *conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	written := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), maxMessage)]
		msg := make([]byte, prefixLen+len(chunk))
		binary.BigEndian.PutUint32(msg[1:], uint32(len(chunk)))
		copy(msg[prefixLen:], chunk)
		if _, err := c.w.Write(msg); err != nil {
			return written, err
		}
		if err := c.flush(); err != nil {
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

// Close must not wait for a Write: the session closes a path exactly when
// its writes may hang, and a blocked Close would stall its watchdog.
func (c *conn) Close() error {
	c.closed.Store(true)
	return c.closeFn()
}

func (c *conn) LocalAddr() net.Addr  { return c.local }
func (c *conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline bounds the session handshake on the call. After the
// handler has returned (the client gave up) there is nothing to bound.
func (c *conn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.ended {
		return net.ErrClosed
	}
	return c.deadline(t)
}
