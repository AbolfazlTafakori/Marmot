package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/session"
	"marmot/internal/socks5"
)

// exitOpener carries the SOCKS5 inbound's connections to a peer that
// delivers them to their destination (exit mode, ADR-0010).
type exitOpener struct{ n *Node }

// socksError carries the SOCKS reply code chosen for a failure.
type socksError struct {
	rep byte
	err error
}

func (e *socksError) Error() string    { return e.err.Error() }
func (e *socksError) Unwrap() error    { return e.err }
func (e *socksError) SocksReply() byte { return e.rep }

// awaiter is implemented by streams that can wait for the far side's
// answer before any data flows.
type awaiter interface {
	AwaitReply(ctx context.Context) error
}

func (o exitOpener) Connect(ctx context.Context, dst socks5.Addr, client netip.AddrPort) (io.ReadWriteCloser, error) {
	return o.open(ctx, core.ProtoTCP, dst, client)
}

func (o exitOpener) Datagram(ctx context.Context, dst socks5.Addr, client netip.AddrPort) (io.ReadWriteCloser, error) {
	return o.open(ctx, core.ProtoUDP, dst, client)
}

// open tries peers in the scheduler's order. A peer that refuses exit by policy
// (its role does not allow it) is skipped; any other answer is final,
// because another exit would reach the same destination the same way.
func (o exitOpener) open(ctx context.Context, proto core.Proto, dst socks5.Addr, client netip.AddrPort) (io.ReadWriteCloser, error) {
	h := frame.StreamHeader{
		Proto: proto, Class: core.ClassTunneled, TargetPort: dst.Port, Client: client,
		Dest: frame.Destination{IP: dst.IP, Host: dst.Host, Port: dst.Port},
	}
	var lastErr error = &socksError{rep: socks5.RepNetworkUnreachable, err: ErrNoRoute}
	for _, s := range o.n.route(nil, proto, h.Class) {
		st, err := s.OpenStream(ctx, h)
		if err != nil {
			lastErr = &socksError{rep: socks5.RepGeneralFailure, err: err}
			continue
		}
		a, ok := st.(awaiter)
		if !ok {
			_ = st.Close()
			return nil, errors.New("node: stream cannot report its reply")
		}
		err = a.AwaitReply(ctx)
		if err == nil {
			return st, nil
		}
		_ = st.Close()
		var re *session.ReplyError
		if errors.As(err, &re) && re.Code == frame.ReplyDenied {
			lastErr = &socksError{rep: socks5.RepNotAllowed, err: fmt.Errorf("peer %s: %w", s.Peer(), err)}
			continue
		}
		return nil, &socksError{rep: socksReplyFor(err), err: fmt.Errorf("peer %s: %w", s.Peer(), err)}
	}
	return nil, lastErr
}

func socksReplyFor(err error) byte {
	var re *session.ReplyError
	if !errors.As(err, &re) {
		return socks5.RepGeneralFailure
	}
	switch re.Code {
	case frame.ReplyRefused:
		return socks5.RepConnectionRefused
	case frame.ReplyUnreachable:
		return socks5.RepHostUnreachable
	case frame.ReplyDenied:
		return socks5.RepNotAllowed
	default:
		return socks5.RepGeneralFailure
	}
}

// applySOCKS5 starts, keeps or restarts the SOCKS5 inbound to match c.
func (n *Node) applySOCKS5(prev, c *config.Config) error {
	n.mu.RLock()
	cur := n.socks
	n.mu.RUnlock()
	if cur != nil && prev != nil && reflect.DeepEqual(prev.SOCKS5, c.SOCKS5) &&
		prev.Session.UDPIdleTimeout == c.Session.UDPIdleTimeout {
		return nil
	}
	if cur != nil {
		_ = cur.Close()
		n.mu.Lock()
		n.socks = nil
		n.mu.Unlock()
	}
	if !c.SOCKS5.Enabled {
		return nil
	}
	listen, err := netip.ParseAddrPort(c.SOCKS5.Listen)
	if err != nil {
		return fmt.Errorf("socks5.listen: %w", err)
	}
	srv, err := socks5.Listen(socks5.Config{
		Listen: listen, Opener: exitOpener{n}, UDPIdleTimeout: c.Session.UDPIdleTimeout.D(),
		Logger: n.log.With("component", "socks5"),
	})
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.socks = srv
	n.mu.Unlock()
	return nil
}
