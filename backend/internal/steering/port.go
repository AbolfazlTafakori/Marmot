package steering

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"marmot/internal/core"
	"marmot/internal/frame"
)

// port is one bound user-facing port (TCP and/or UDP).
type port struct {
	s      *Steering
	r      atomic.Pointer[Rule]
	tcp    *net.TCPListener
	udp    *udpPort
	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup

	// Bytes from users into the tunnel and back, counted as they flow.
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// listen binds r's protocols on all addresses (dual stack).
func listen(s *Steering, r Rule) (*port, error) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &port{s: s, ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
	p.r.Store(&r)
	if r.has(core.ProtoTCP) {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: int(r.Port)})
		if err != nil {
			cancel()
			return nil, err
		}
		p.tcp = l
	}
	if r.has(core.ProtoUDP) {
		c, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(r.Port)})
		if err != nil {
			if p.tcp != nil {
				_ = p.tcp.Close()
			}
			cancel()
			return nil, err
		}
		p.udp = newUDPPort(p, c)
	}
	if p.tcp != nil {
		p.wg.Add(1)
		go p.acceptLoop()
	}
	if p.udp != nil {
		p.wg.Add(2)
		go p.udp.readLoop()
		go p.udp.janitor()
	}
	return p, nil
}

func (p *port) rule() Rule     { return *p.r.Load() }
func (p *port) setRule(r Rule) { p.r.Store(&r) }

func (p *port) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.tcp.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			p.s.log.Warn("accept failed", "port", p.rule().Port, "err", err)
			continue
		}
		if !p.track(c) {
			_ = c.Close()
			return
		}
		p.wg.Add(1)
		go p.handleTCP(c)
	}
}

func (p *port) handleTCP(c *net.TCPConn) {
	defer p.wg.Done()
	defer p.untrack(c)
	r := p.rule()
	client, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		_ = c.Close()
		return
	}
	h := frame.StreamHeader{Proto: core.ProtoTCP, Class: r.Class, TargetPort: r.TargetPort, Client: client}
	ctx, cancel := context.WithTimeout(p.ctx, openTimeout)
	st, err := p.s.cfg.Opener.Open(ctx, r, h)
	cancel()
	if err != nil {
		p.s.log.Debug("no stream for connection", "port", r.Port, "err", err)
		_ = c.Close()
		return
	}
	core.Pipe(&countedConn{Conn: c, in: &p.bytesIn, out: &p.bytesOut}, st)
}

// countedConn counts a user connection's bytes as they pass, so traffic
// statistics move while long connections are still open.
type countedConn struct {
	net.Conn
	in, out *atomic.Int64
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.in.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.out.Add(int64(n))
	return n, err
}

// track registers c so close can end it; it fails once the port closes.
func (p *port) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *port) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *port) active() (tcp, udp int) {
	p.mu.Lock()
	tcp = len(p.conns)
	p.mu.Unlock()
	if p.udp != nil {
		udp = p.udp.count()
	}
	return tcp, udp
}

// close unbinds the port, ends its connections and flows, and waits.
func (p *port) close() {
	p.cancel()
	if p.tcp != nil {
		_ = p.tcp.Close()
	}
	if p.udp != nil {
		p.udp.close()
	}
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}
