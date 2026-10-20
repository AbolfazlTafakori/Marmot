// Package forwarder delivers streams that arrive from a peer to the local
// target (the panel inbound), prepending PROXY v2 when configured.
package forwarder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/proxyproto"
	"marmot/internal/session"
)

// DialTimeout bounds the connection to the local target.
const DialTimeout = 5 * time.Second

// Policy decides how streams are delivered. It is replaced as a whole on
// reload.
type Policy struct {
	TargetHost string
	ProxyV2    bool
	// ProxyV2Ports limits PROXY v2 to these target ports; empty = all.
	ProxyV2Ports map[uint16]bool
	// DeniedPorts may never be targeted by a peer: SSH and the panel API.
	DeniedPorts map[uint16]bool
	AllowUDP    bool
	// AllowExit lets peers send exit streams through this node (role exit
	// or hybrid, ADR-0010).
	AllowExit bool
	// AllowDestination decides which addresses an exit may connect to;
	// nil means the ADR-0010 rule (no private, local or own addresses).
	AllowDestination func(netip.Addr) bool
	UDPIdleTimeout   time.Duration
}

func (p *Policy) validate() error {
	if p.TargetHost == "" {
		return errors.New("forwarder: target host required")
	}
	if p.AllowUDP && p.UDPIdleTimeout <= 0 {
		return errors.New("forwarder: udp idle timeout must be positive")
	}
	return nil
}

// Stats are cumulative counters.
type Stats struct {
	Streams  int64
	Active   int64
	Refused  int64
	BytesIn  int64 // from peers to targets
	BytesOut int64 // from targets to peers
}

// Forwarder serves accepted streams.
type Forwarder struct {
	policy atomic.Pointer[Policy]
	log    *slog.Logger

	streams, active, refused, bytesIn, bytesOut atomic.Int64
}

// New creates a forwarder.
func New(p Policy, log *slog.Logger) (*Forwarder, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	f := &Forwarder{log: log}
	f.policy.Store(&p)
	return f, nil
}

// SetPolicy replaces the policy for streams accepted from now on.
func (f *Forwarder) SetPolicy(p Policy) error {
	if err := p.validate(); err != nil {
		return err
	}
	f.policy.Store(&p)
	return nil
}

// Stats returns the counters.
func (f *Forwarder) Stats() Stats {
	return Stats{Streams: f.streams.Load(), Active: f.active.Load(), Refused: f.refused.Load(),
		BytesIn: f.bytesIn.Load(), BytesOut: f.bytesOut.Load()}
}

// Serve delivers one stream and returns when it ends. It owns st.
func (f *Forwarder) Serve(ctx context.Context, st session.Stream, h frame.StreamHeader) {
	f.streams.Add(1)
	f.active.Add(1)
	defer f.active.Add(-1)
	p := f.policy.Load()

	if code := f.check(p, h); code != frame.ReplyOK {
		f.refuse(st, code)
		return
	}
	if !h.Dest.IsZero() {
		f.serveExit(ctx, p, st, h)
		return
	}
	target := net.JoinHostPort(p.TargetHost, strconv.Itoa(int(h.TargetPort)))
	switch h.Proto {
	case core.ProtoTCP:
		f.serveTCP(ctx, p, st, h, target)
	case core.ProtoUDP:
		f.serveUDP(ctx, p, st, target)
	}
}

func (f *Forwarder) check(p *Policy, h frame.StreamHeader) byte {
	switch {
	case len(h.Route) > 0:
		// Relay transit arrives with session routing in Phase 2.
		f.log.Warn("relay route requested but transit is not available", "route", h.Route)
		return frame.ReplyDenied
	case h.Dest.IsZero() && p.DeniedPorts[h.TargetPort]:
		f.log.Warn("stream to a protected port denied", "port", h.TargetPort)
		return frame.ReplyDenied
	case h.Proto == core.ProtoUDP && !p.AllowUDP:
		return frame.ReplyDenied
	}
	return frame.ReplyOK
}

func (f *Forwarder) refuse(st session.Stream, code byte) {
	f.refused.Add(1)
	_, _ = st.Write([]byte{code})
	_ = st.Close()
}

func (f *Forwarder) serveTCP(ctx context.Context, p *Policy, st session.Stream, h frame.StreamHeader, target string) {
	d := net.Dialer{Timeout: DialTimeout}
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		f.log.Debug("target dial failed", "target", target, "err", err)
		f.refuse(st, dialErrorCode(err))
		return
	}
	if p.ProxyV2 && (len(p.ProxyV2Ports) == 0 || p.ProxyV2Ports[h.TargetPort]) {
		if err := writeProxyHeader(c, h.Client); err != nil {
			_ = c.Close()
			f.refuse(st, frame.ReplyUnreachable)
			return
		}
	}
	if _, err := st.Write([]byte{frame.ReplyOK}); err != nil {
		_ = c.Close()
		_ = st.Close()
		return
	}
	in, out := core.Pipe(st, c)
	f.bytesIn.Add(in)
	f.bytesOut.Add(out)
}

func writeProxyHeader(c net.Conn, client netip.AddrPort) error {
	dst, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("target address: %w", err)
	}
	h := proxyproto.Header{Command: proxyproto.CmdProxy, Proto: core.ProtoTCP, Src: client, Dst: dst}
	var buf [64]byte
	b, err := h.Append(buf[:0])
	if err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

func dialErrorCode(err error) byte {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return frame.ReplyRefused
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return frame.ReplyUnreachable
	}
	return frame.ReplyRefused
}
