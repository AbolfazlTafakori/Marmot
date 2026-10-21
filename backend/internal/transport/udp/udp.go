// Package udp is the plain UDP transport (ADR-0016): session v2 records in
// UDP datagrams, paced and congestion-controlled by the session itself,
// so random loss that FEC repairs does not slow the path as QUIC's Cubic
// does.
//
// Each datagram starts with a kind byte. The Noise handshake runs over a
// tiny request/reply retransmission scheme exposed as the Conn's stream;
// after it, only records and close travel.
package udp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"marmot/internal/transport"
)

// Name is the registered transport name.
const Name = "udp"

// Datagram kinds.
const (
	kindHandshake = 1
	kindRecord    = 2
	kindClose     = 3
)

const (
	maxDatagram = 1200 // as for QUIC: safe on any path
	hsRetry     = 250 * time.Millisecond
	hsTimeout   = 10 * time.Second
	idleTimeout = 60 * time.Second
	maxConns    = 1024
	recvQueue   = 512
	readBuf     = 64 << 10
)

// errClosed is returned once a connection has ended.
var errClosed = net.ErrClosed

func init() { transport.Register(Transport{}) }

// Transport is plain UDP. It has no options.
type Transport struct{}

// Name implements transport.Transport.
func (Transport) Name() string { return Name }

// Kind implements transport.Transport.
func (Transport) Kind() transport.Kind { return transport.Datagram }

// Dial implements transport.Transport: a connection with its own socket,
// bound to local when it is valid.
func (Transport) Dial(ctx context.Context, ep transport.Endpoint, local netip.Addr) (transport.Conn, error) {
	laddr := &net.UDPAddr{}
	if local.IsValid() {
		laddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0))
	}
	lc := net.ListenConfig{Control: transport.FreebindControl}
	pc, err := lc.ListenPacket(ctx, "udp", laddr.String())
	if err != nil {
		return nil, fmt.Errorf("udp: bind %v: %w", laddr, err)
	}
	sock := pc.(*net.UDPConn)
	raddr := netip.AddrPortFrom(ep.Addr.Addr().Unmap(), ep.Addr.Port())
	c := newConn(sock, raddr, true, nil)
	go c.readOwn()
	return c, nil
}

// Listen implements transport.Transport.
func (Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", cfg.Addr.String())
	if err != nil {
		return nil, err
	}
	l := &listener{sock: pc.(*net.UDPConn), conns: map[netip.AddrPort]*conn{},
		accept: make(chan *conn, 64), done: make(chan struct{})}
	l.wg.Add(2)
	go l.readLoop()
	go l.reap()
	return l, nil
}

// listener tells peers apart by address and port on one socket.
type listener struct {
	sock   *net.UDPConn
	mu     sync.Mutex
	conns  map[netip.AddrPort]*conn
	accept chan *conn
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func (l *listener) readLoop() {
	defer l.wg.Done()
	buf := make([]byte, readBuf)
	for {
		n, from, err := l.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		l.mu.Lock()
		c := l.conns[from]
		if c == nil && buf[0] == kindHandshake && len(l.conns) < maxConns {
			c = newConn(l.sock, from, false, l.forget)
			l.conns[from] = c
			select {
			case l.accept <- c:
			default: // nobody accepts fast enough: drop it
				delete(l.conns, from)
				c = nil
			}
		}
		l.mu.Unlock()
		if c != nil {
			c.receive(buf[:n])
		}
	}
}

// reap closes connections that have been silent for idleTimeout.
func (l *listener) reap() {
	defer l.wg.Done()
	t := time.NewTicker(idleTimeout / 6)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
		}
		l.mu.Lock()
		var idle []*conn
		for _, c := range l.conns {
			if c.idle() > idleTimeout {
				idle = append(idle, c)
			}
		}
		l.mu.Unlock()
		for _, c := range idle {
			_ = c.Close()
		}
	}
}

func (l *listener) forget(c *conn) {
	l.mu.Lock()
	if l.conns[c.raddr] == c {
		delete(l.conns, c.raddr)
	}
	l.mu.Unlock()
}

// Accept implements transport.Listener.
func (l *listener) Accept() (transport.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, errClosed
	}
}

// Close implements transport.Listener: the socket closes, and with it
// every connection on it.
func (l *listener) Close() error {
	l.once.Do(func() {
		close(l.done)
		_ = l.sock.Close()
	})
	l.wg.Wait()
	l.mu.Lock()
	all := make([]*conn, 0, len(l.conns))
	for _, c := range l.conns {
		all = append(all, c)
	}
	l.mu.Unlock()
	for _, c := range all {
		c.end()
	}
	return nil
}

// Addr implements transport.Listener.
func (l *listener) Addr() net.Addr { return l.sock.LocalAddr() }

// errTimeout is returned by Read and Write after their deadline.
type errTimeout struct{}

func (errTimeout) Error() string   { return "udp: i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }
