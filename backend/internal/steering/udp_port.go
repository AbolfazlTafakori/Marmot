package steering

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/session"
)

// flowQueue is how many datagrams may wait for a slow stream; beyond it
// datagrams are dropped, as a congested router would.
const flowQueue = 128

// udpPort demultiplexes one UDP socket into flows keyed by client address;
// each flow is one stream.
type udpPort struct {
	p    *port
	conn *net.UDPConn

	mu    sync.Mutex
	flows map[netip.AddrPort]*udpFlow
}

type udpFlow struct {
	u      *udpPort
	client netip.AddrPort
	queue  chan *[]byte
	done   chan struct{}
	last   atomic.Int64

	once sync.Once
	mu   sync.Mutex
	st   session.Stream
}

func newUDPPort(p *port, c *net.UDPConn) *udpPort {
	return &udpPort{p: p, conn: c, flows: make(map[netip.AddrPort]*udpFlow)}
}

func (u *udpPort) readLoop() {
	defer u.p.wg.Done()
	buf := make([]byte, frame.MaxDatagram)
	for {
		n, from, err := u.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // e.g. ICMP port unreachable reported on Windows
		}
		f := u.flow(from)
		if f == nil {
			return
		}
		u.p.bytesIn.Add(int64(n))
		pkt := core.GetBuf(n)
		copy(*pkt, buf[:n])
		select {
		case f.queue <- pkt:
		default:
			core.PutBuf(pkt)
		}
	}
}

// flow returns the flow for client, starting one if needed. It returns nil
// once the port is closing.
func (u *udpPort) flow(client netip.AddrPort) *udpFlow {
	u.mu.Lock()
	defer u.mu.Unlock()
	if f := u.flows[client]; f != nil {
		return f
	}
	if u.p.ctx.Err() != nil {
		return nil
	}
	f := &udpFlow{u: u, client: client, queue: make(chan *[]byte, flowQueue), done: make(chan struct{})}
	f.touch()
	u.flows[client] = f
	u.p.wg.Add(1)
	go f.run()
	return f
}

func (u *udpPort) remove(f *udpFlow) {
	u.mu.Lock()
	if u.flows[f.client] == f {
		delete(u.flows, f.client)
	}
	u.mu.Unlock()
}

func (u *udpPort) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.flows)
}

// janitor ends flows that have been idle for the configured timeout.
func (u *udpPort) janitor() {
	defer u.p.wg.Done()
	idle := u.p.s.cfg.UDPIdleTimeout
	t := time.NewTicker(idle / 4)
	defer t.Stop()
	for {
		select {
		case <-u.p.ctx.Done():
			return
		case <-t.C:
		}
		u.mu.Lock()
		var stale []*udpFlow
		for _, f := range u.flows {
			if time.Since(time.Unix(0, f.last.Load())) > idle {
				stale = append(stale, f)
			}
		}
		u.mu.Unlock()
		for _, f := range stale {
			f.close()
		}
	}
}

func (u *udpPort) close() {
	_ = u.conn.Close()
	u.mu.Lock()
	all := make([]*udpFlow, 0, len(u.flows))
	for _, f := range u.flows {
		all = append(all, f)
	}
	u.mu.Unlock()
	for _, f := range all {
		f.close()
	}
}

func (f *udpFlow) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *udpFlow) close() {
	f.once.Do(func() {
		close(f.done)
		f.mu.Lock()
		if f.st != nil {
			_ = f.st.Close()
		}
		f.mu.Unlock()
		f.u.remove(f)
	})
}

// run opens the flow's stream and pumps datagrams both ways.
func (f *udpFlow) run() {
	defer f.u.p.wg.Done()
	defer f.drain()
	defer f.close()
	r := f.u.p.rule()
	h := frame.StreamHeader{Proto: core.ProtoUDP, Class: r.Class, TargetPort: r.TargetPort, Client: f.client}
	ctx, cancel := context.WithTimeout(f.u.p.ctx, openTimeout)
	st, err := f.u.p.s.cfg.Opener.Open(ctx, r, h)
	cancel()
	if err != nil {
		f.u.p.s.log.Debug("no stream for udp flow", "port", r.Port, "err", err)
		return
	}
	f.mu.Lock()
	f.st = st
	f.mu.Unlock()
	select {
	case <-f.done: // closed while opening
		_ = st.Close()
		return
	default:
	}

	f.u.p.wg.Add(1)
	go f.downlink(st)
	scratch := make([]byte, 2+frame.MaxDatagram)
	for {
		select {
		case <-f.done:
			return
		case pkt := <-f.queue:
			err := frame.WriteDatagram(st, scratch, *pkt)
			core.PutBuf(pkt)
			if err != nil {
				return
			}
			f.touch()
		}
	}
}

func (f *udpFlow) downlink(st session.Stream) {
	defer f.u.p.wg.Done()
	defer f.close()
	buf := make([]byte, frame.MaxDatagram)
	for {
		n, err := frame.ReadDatagram(st, buf)
		if err != nil {
			return
		}
		f.touch()
		if _, err := f.u.conn.WriteToUDPAddrPort(buf[:n], f.client); err != nil {
			return
		}
		f.u.p.bytesOut.Add(int64(n))
	}
}

// drain returns queued buffers to the pool after the flow ends.
func (f *udpFlow) drain() {
	for {
		select {
		case pkt := <-f.queue:
			core.PutBuf(pkt)
		default:
			return
		}
	}
}
