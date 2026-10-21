// Package quic is the QUIC transport (ADR-0014). A path is one QUIC
// connection: its first bidirectional stream carries the Noise handshake
// and, in session v1, the records. When both ends enabled RFC 9221
// datagrams, session v2 moves the path's records into datagrams, where
// they may be lost and FEC applies.
//
// TLS inside QUIC is camouflage, not authentication: as with the tls
// transport, the peer is authenticated by Noise against a pinned key, so
// the client does not verify the certificate and the server may use a
// self-signed one.
package quic

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"marmot/internal/transport"
	"marmot/internal/transport/tls"
)

// Name is the registered transport name.
const Name = "quic"

const (
	defaultALPN = "h3" // looks like HTTP/3
	// maxDatagram stays under what QUIC accepts at its smallest packet
	// size (1,280 bytes), so it holds for the life of the connection.
	maxDatagram       = 1200
	handshakeTimeout  = 10 * time.Second
	idleTimeout       = 30 * time.Second
	maxPendingStreams = 256
)

func init() { transport.Register(Transport{}) }

// Transport is QUIC.
//
// Endpoint options: sni (string), alpn (string, default "h3"), datagrams
// (bool, default true; false keeps every record on the stream).
// Listen options: cert_file, key_file and sni as for tls, alpn.
type Transport struct{}

// Name implements transport.Transport.
func (Transport) Name() string { return Name }

// Kind implements transport.Transport: QUIC runs over UDP and its paths
// can carry datagrams.
func (Transport) Kind() transport.Kind { return transport.Datagram }

func quicConfig(datagrams bool) *quicgo.Config {
	return &quicgo.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       idleTimeout,
		EnableDatagrams:      datagrams,
	}
}

// Dial implements transport.Transport. Each connection has its own UDP
// socket, bound to local when it is valid, and closes it when it ends.
func (Transport) Dial(ctx context.Context, ep transport.Endpoint, local netip.Addr) (transport.Conn, error) {
	sni, err := transport.StringOption(ep.Options, "sni", "")
	if err != nil {
		return nil, err
	}
	alpn, err := transport.StringOption(ep.Options, "alpn", defaultALPN)
	if err != nil {
		return nil, err
	}
	datagrams, err := transport.BoolOption(ep.Options, "datagrams", true)
	if err != nil {
		return nil, err
	}
	laddr := &net.UDPAddr{}
	if local.IsValid() {
		laddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0))
	}
	lc := net.ListenConfig{Control: transport.FreebindControl} // a rotating /64 source (ADR-0018)
	pc, err := lc.ListenPacket(ctx, "udp", laddr.String())
	if err != nil {
		return nil, fmt.Errorf("quic: bind %v: %w", laddr, err)
	}
	udp := pc.(*net.UDPConn)
	tr := &quicgo.Transport{Conn: udp}
	conf := &stdtls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // Noise authenticates the peer; see the package comment
		NextProtos:         []string{alpn},
		MinVersion:         stdtls.VersionTLS13,
	}
	qc, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(ep.Addr), conf, quicConfig(datagrams))
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("quic dial %s: %w", ep.Addr, err)
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "")
		_ = tr.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("quic open stream %s: %w", ep.Addr, err)
	}
	return newConn(qc, st, func() { _ = tr.Close(); _ = udp.Close() }), nil
}

// Listen implements transport.Transport.
func (Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	alpn, err := transport.StringOption(cfg.Options, "alpn", defaultALPN)
	if err != nil {
		return nil, err
	}
	conf, err := tls.ServerConfig(cfg.Options, []string{alpn})
	if err != nil {
		return nil, err
	}
	conf.MinVersion = stdtls.VersionTLS13
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", cfg.Addr.String())
	if err != nil {
		return nil, err
	}
	udp := pc.(*net.UDPConn)
	tr := &quicgo.Transport{Conn: udp}
	ln, err := tr.Listen(conf, quicConfig(true))
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, err
	}
	lctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l := &listener{tr: tr, udp: udp, ln: ln, ctx: lctx, cancel: cancel, ready: make(chan transport.Conn),
		done: make(chan struct{}), sem: make(chan struct{}, maxPendingStreams)}
	l.wg.Add(1)
	go l.loop()
	return l, nil
}

// listener accepts QUIC connections and returns each one once its first
// stream has arrived, so a slow client never blocks Accept.
type listener struct {
	tr     *quicgo.Transport
	udp    *net.UDPConn
	ln     *quicgo.Listener
	ctx    context.Context // ends when the listener closes
	cancel context.CancelFunc
	ready  chan transport.Conn
	done   chan struct{}
	sem    chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func (l *listener) loop() {
	defer l.wg.Done()
	for {
		qc, err := l.ln.Accept(l.ctx)
		if err != nil {
			return
		}
		select {
		case l.sem <- struct{}{}:
		default:
			_ = qc.CloseWithError(0, "")
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer func() { <-l.sem }()
			l.firstStream(qc)
		}()
	}
}

func (l *listener) firstStream(qc *quicgo.Conn) {
	ctx, cancel := context.WithTimeout(qc.Context(), handshakeTimeout)
	defer cancel()
	st, err := qc.AcceptStream(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "")
		return
	}
	c := newConn(qc, st, nil)
	select {
	case l.ready <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// Accept implements transport.Listener.
func (l *listener) Accept() (transport.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close implements transport.Listener. Connections already accepted stay
// open; their sessions close them.
func (l *listener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.cancel()
		_ = l.ln.Close()
	})
	l.wg.Wait()
	return nil
}

// Addr implements transport.Listener.
func (l *listener) Addr() net.Addr { return l.ln.Addr() }

// conn is one QUIC connection seen as a transport.Conn: its first stream,
// plus the connection's datagrams.
type conn struct {
	qc      *quicgo.Conn
	st      *quicgo.Stream
	release func() // closes a dialer's own UDP socket; nil when accepted
	dg      bool
	once    sync.Once
}

var (
	_ transport.Conn        = (*conn)(nil)
	_ transport.Datagrammer = (*conn)(nil)
)

func newConn(qc *quicgo.Conn, st *quicgo.Stream, release func()) *conn {
	s := qc.ConnectionState().SupportsDatagrams
	return &conn{qc: qc, st: st, release: release, dg: s.Local && s.Remote}
}

func (c *conn) Read(b []byte) (int, error)  { return c.st.Read(b) }
func (c *conn) Write(b []byte) (int, error) { return c.st.Write(b) }

// SetDeadline bounds reads and writes on the stream (the session layer
// uses it for the handshake).
func (c *conn) SetDeadline(t time.Time) error { return c.st.SetDeadline(t) }

// Close closes the whole QUIC connection, and the dialer's socket.
func (c *conn) Close() error {
	c.once.Do(func() {
		c.st.CancelRead(0)
		_ = c.st.Close()
		_ = c.qc.CloseWithError(0, "")
		if c.release != nil {
			c.release()
		}
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

// DatagramsEnabled implements transport.Datagrammer: true only when both
// ends enabled datagrams, so both see the same value.
func (c *conn) DatagramsEnabled() bool { return c.dg }

// MaxDatagramSize implements transport.Datagrammer.
func (c *conn) MaxDatagramSize() int { return maxDatagram }

// SendDatagram implements transport.Datagrammer. It blocks while QUIC's
// queue is full, which is the path's backpressure.
func (c *conn) SendDatagram(b []byte) error {
	err := c.qc.SendDatagram(b)
	var tooLarge *quicgo.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return fmt.Errorf("quic: datagram of %d bytes over the path limit %d: %w", len(b), tooLarge.MaxDatagramPayloadSize, err)
	}
	return err
}

// ReceiveDatagram implements transport.Datagrammer.
func (c *conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.qc.ReceiveDatagram(ctx)
}
