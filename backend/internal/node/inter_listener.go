package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"marmot/internal/config"
	"marmot/internal/session"
	"marmot/internal/transport"
)

// maxPendingHandshakes bounds unauthenticated connections per listener, so
// a flood of junk connections cannot exhaust memory.
const maxPendingHandshakes = 256

// interListener accepts inter-node connections on one transport and port
// and hands them to the acceptor.
type interListener struct {
	key       string
	transport string
	l         transport.Listener
	sem       chan struct{}
	wg        sync.WaitGroup
}

func listenerKey(tl config.TransportListen) string {
	return fmt.Sprintf("%s|%d|%v", tl.Transport, tl.Port, tl.Options)
}

func startInterListener(ctx context.Context, tl config.TransportListen, acc *session.Acceptor, log *slog.Logger) (*interListener, error) {
	tr, err := transport.Get(tl.Transport)
	if err != nil {
		return nil, err
	}
	l, err := tr.Listen(ctx, transport.ListenConfig{
		Addr:    netip.AddrPortFrom(netip.IPv6Unspecified(), tl.Port),
		Options: tl.Options,
	})
	if err != nil {
		return nil, err
	}
	il := &interListener{key: listenerKey(tl), transport: tl.Transport, l: l, sem: make(chan struct{}, maxPendingHandshakes)}
	il.wg.Add(1)
	go il.acceptLoop(ctx, acc, log)
	log.Info("inter-node listener up", "transport", tl.Transport, "addr", l.Addr().String())
	return il, nil
}

func (il *interListener) acceptLoop(ctx context.Context, acc *session.Acceptor, log *slog.Logger) {
	defer il.wg.Done()
	for {
		c, err := il.l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			log.Warn("inter-node accept failed", "err", err)
			continue
		}
		select {
		case il.sem <- struct{}{}:
		default:
			_ = c.Close() // too many handshakes in flight
			continue
		}
		meta := session.PathMeta{Transport: il.transport, Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}
		il.wg.Add(1)
		go func() {
			defer il.wg.Done()
			defer func() { <-il.sem }()
			if err := acc.Handle(ctx, c, meta); err != nil {
				log.Debug("inbound path rejected", "remote", meta.Remote, "err", err)
			}
		}()
	}
}

func (il *interListener) addr() string { return il.l.Addr().String() }

func (il *interListener) close() {
	_ = il.l.Close()
	il.wg.Wait()
}

// applyListeners makes the running inter-node listeners match c: unchanged
// ones stay, removed ones close, new ones open. A port_range listener of a
// datagram transport (quic) binds every port of the range (ADR-0014 §3).
// Transports this build does not have are skipped with a warning, so a
// config written for a later phase still runs.
func (n *Node) applyListeners(c *config.Config) error {
	n.mu.RLock()
	ctx, acc, current := n.ctx, n.acceptor, n.listeners
	n.mu.RUnlock()

	want := map[string]config.TransportListen{}
	for _, tl := range c.TransportListen {
		tr, err := transport.Get(tl.Transport)
		if err != nil {
			n.log.Warn("transport not available in this build; listener skipped", "transport", tl.Transport)
			continue
		}
		if tl.Port != 0 {
			want[listenerKey(tl)] = tl
			continue
		}
		if tr.Kind() != transport.Datagram {
			n.log.Warn("port_range listeners need a datagram transport; listener skipped", "transport", tl.Transport)
			continue
		}
		for p := uint32(tl.PortRange.Lo); p <= uint32(tl.PortRange.Hi); p++ {
			one := tl
			one.Port, one.PortRange = uint16(p), config.PortRange{}
			want[listenerKey(one)] = one
		}
	}
	next := map[string]*interListener{}
	var stale []*interListener
	for k, il := range current {
		if _, keep := want[k]; keep {
			next[k] = il
			delete(want, k)
		} else {
			stale = append(stale, il)
		}
	}
	for _, il := range stale {
		il.close()
	}
	var errs []error
	for k, tl := range want {
		il, err := startInterListener(ctx, tl, acc, n.log.With("component", "listener"))
		if err != nil {
			errs = append(errs, fmt.Errorf("listen %s :%d: %w", tl.Transport, tl.Port, err))
			continue
		}
		next[k] = il
	}
	n.mu.Lock()
	n.listeners = next
	n.mu.Unlock()
	return errors.Join(errs...)
}
