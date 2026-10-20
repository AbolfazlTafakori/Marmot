package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
)

// flowQueue bounds datagrams waiting for a slow stream; beyond it they are
// dropped, as a congested router would.
const flowQueue = 128

// association is one UDP ASSOCIATE: a UDP socket for the client, and one
// stream per destination it sends to.
type association struct {
	s        *Server
	uc       *net.UDPConn
	clientIP netip.Addr // datagrams from any other host are ignored (RFC 1928 §7)
	client   atomic.Pointer[netip.AddrPort]
	ctx      context.Context
	end      context.CancelFunc

	mu    sync.Mutex
	flows map[string]*udpFlow
	wg    sync.WaitGroup
}

type udpFlow struct {
	a     *association
	dst   Addr
	key   string
	queue chan *[]byte
	done  chan struct{}
	last  atomic.Int64
	once  sync.Once
	mu    sync.Mutex
	st    io.ReadWriteCloser
}

// associate serves UDP ASSOCIATE until the control connection closes.
func (s *Server) associate(c *net.TCPConn, client netip.AddrPort) {
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.Addr().AsSlice()})
	if err != nil {
		_ = writeReply(c, RepGeneralFailure, Addr{})
		return
	}
	bound := uc.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := writeReply(c, RepSucceeded, Addr{IP: bound.Addr().Unmap(), Port: bound.Port()}); err != nil {
		_ = uc.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	ctx, end := context.WithCancel(s.ctx)
	a := &association{s: s, uc: uc, clientIP: client.Addr().Unmap(), ctx: ctx, end: end, flows: map[string]*udpFlow{}}

	// The association lives as long as the TCP connection that made it.
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		_, _ = io.Copy(io.Discard, c)
		a.close()
	}()
	go a.janitor()
	a.readLoop()
	a.close()
	_ = c.Close()
	a.wg.Wait()
}

func (a *association) close() {
	a.end()
	_ = a.uc.Close()
	a.mu.Lock()
	all := make([]*udpFlow, 0, len(a.flows))
	for _, f := range a.flows {
		all = append(all, f)
	}
	a.mu.Unlock()
	for _, f := range all {
		f.close()
	}
}

func (a *association) readLoop() {
	buf := make([]byte, frame.MaxDatagram)
	for {
		n, from, err := a.uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || a.ctx.Err() != nil {
				return
			}
			continue
		}
		if from.Addr().Unmap() != a.clientIP {
			continue
		}
		a.client.Store(&from)
		dst, data, err := parseUDP(buf[:n])
		if err != nil {
			continue
		}
		f := a.flow(dst)
		if f == nil {
			return
		}
		pkt := core.GetBuf(len(data))
		copy(*pkt, data)
		select {
		case f.queue <- pkt:
		default:
			core.PutBuf(pkt)
		}
	}
}

func (a *association) flow(dst Addr) *udpFlow {
	key := dst.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	if f := a.flows[key]; f != nil {
		return f
	}
	if a.ctx.Err() != nil {
		return nil
	}
	f := &udpFlow{a: a, dst: dst, key: key, queue: make(chan *[]byte, flowQueue), done: make(chan struct{})}
	f.touch()
	a.flows[key] = f
	a.wg.Add(1)
	go f.run()
	return f
}

func (a *association) remove(f *udpFlow) {
	a.mu.Lock()
	if a.flows[f.key] == f {
		delete(a.flows, f.key)
	}
	a.mu.Unlock()
}

// janitor ends flows that have been idle for the configured timeout.
func (a *association) janitor() {
	defer a.wg.Done()
	idle := a.s.cfg.UDPIdleTimeout
	t := time.NewTicker(idle / 4)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		var stale []*udpFlow
		for _, f := range a.flows {
			if time.Since(time.Unix(0, f.last.Load())) > idle {
				stale = append(stale, f)
			}
		}
		a.mu.Unlock()
		for _, f := range stale {
			f.close()
		}
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
		f.a.remove(f)
	})
}

func (f *udpFlow) run() {
	defer f.a.wg.Done()
	defer f.drain()
	defer f.close()
	client := f.a.client.Load()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(f.a.ctx, handshakeTimeout)
	st, err := f.a.s.cfg.Opener.Datagram(ctx, f.dst, *client)
	cancel()
	if err != nil {
		f.a.s.log.Debug("socks5 udp flow failed", "dst", f.key, "err", err)
		return
	}
	f.mu.Lock()
	f.st = st
	f.mu.Unlock()
	select {
	case <-f.done:
		_ = st.Close()
		return
	default:
	}
	f.a.wg.Add(1)
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

// downlink returns the destination's datagrams to the client, each with
// the SOCKS UDP header naming the destination as the source.
func (f *udpFlow) downlink(st io.Reader) {
	defer f.a.wg.Done()
	defer f.close()
	buf := make([]byte, frame.MaxDatagram)
	out := make([]byte, 0, 262+frame.MaxDatagram)
	for {
		n, err := frame.ReadDatagram(st, buf)
		if err != nil {
			return
		}
		f.touch()
		client := f.a.client.Load()
		if client == nil {
			continue
		}
		out = appendUDP(out[:0], f.dst, buf[:n])
		if _, err := f.a.uc.WriteToUDPAddrPort(out, *client); err != nil {
			return
		}
	}
}

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
