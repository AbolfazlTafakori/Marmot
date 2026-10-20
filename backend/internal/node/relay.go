package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/mesh"
	"marmot/internal/session"
	"marmot/internal/transport"
)

// Relay routing (ADR-0012): a relayed path is a path of the end-to-end
// session that runs inside a path stream through a relay node. The relay
// pipes ciphertext of the end-to-end session; it never sees user bytes.
//
// Only sessions whose active path is direct carry path streams, at the
// origin and at every relay, so relayed paths never nest.

// relayReplyTimeout bounds the wait for each hop to answer a path stream.
const relayReplyTimeout = 10 * time.Second

// relayMetaPrefix marks the remote of a relayed path in PathMeta.
const relayMetaPrefix = "via "

// errNoDirectSession means the node has no session with a direct active
// path to the next hop.
var errNoDirectSession = errors.New("node: no direct session to next hop")

// relayAddr is the address of either end of a relayed path.
type relayAddr string

func (a relayAddr) Network() string { return "marmot-relay" }
func (a relayAddr) String() string  { return string(a) }

// streamConn adapts a path stream to transport.Conn.
type streamConn struct {
	session.Stream
	local, remote relayAddr
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline lets the session layer bound the handshake on a relayed path.
func (c *streamConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

// directSession returns a live, ready session to id whose active path is
// direct: the outbound one if it qualifies, else the newest inbound one.
func (n *Node) directSession(id core.NodeID) session.PeerSession {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.running {
		return nil
	}
	if l := n.links[id]; l != nil {
		if s := l.session(); s != nil && directReady(s) {
			return s
		}
	}
	var best session.PeerSession
	for _, s := range n.acceptor.Sessions() {
		if s.Peer() == id && directReady(s) && (best == nil || s.Started().After(best.Started())) {
			best = s
		}
	}
	return best
}

// directReady reports whether s is live, ready and runs on a direct path.
func directReady(s session.PeerSession) bool {
	if !live(s) {
		return false
	}
	st := s.Stats()
	if !st.Ready {
		return false
	}
	for i := range st.Paths {
		if st.Paths[i].Active {
			return !isRelayed(st.Paths[i].Meta)
		}
	}
	return false
}

func isRelayed(m session.PathMeta) bool { return m.Transport == mesh.TransportRelay }

// relayVias lists the peers that could relay a path to target: every other
// configured peer with a direct session. Whether a peer allows transit is
// learned by trying; a refusal quarantines that relay.
func (n *Node) relayVias(target core.NodeID) []core.NodeID {
	n.mu.RLock()
	if !n.running || n.cfg.Relay.MaxHops < 2 {
		n.mu.RUnlock()
		return nil
	}
	ids := make([]core.NodeID, 0, len(n.cfg.Peers))
	for i := range n.cfg.Peers {
		if id := core.NodeID(n.cfg.Peers[i].ID); id != target {
			ids = append(ids, id)
		}
	}
	n.mu.RUnlock()
	out := ids[:0]
	for _, id := range ids {
		if n.directSession(id) != nil {
			out = append(out, id)
		}
	}
	return out
}

// dialRelay opens a path stream to target through via and waits until
// every hop has answered.
func (n *Node) dialRelay(ctx context.Context, via, target core.NodeID) (transport.Conn, error) {
	s := n.directSession(via)
	if s == nil {
		return nil, fmt.Errorf("relay %s: %w", via, errNoDirectSession)
	}
	return openPath(ctx, s, []core.NodeID{target}, relayAddr(n.Config().Node.ID), relayAddr(relayMetaPrefix+string(via)))
}

// openPath opens a path stream with route on s and waits for its answer.
func openPath(ctx context.Context, s session.PeerSession, route []core.NodeID, local, remote relayAddr) (transport.Conn, error) {
	st, err := s.OpenStream(ctx, frame.StreamHeader{Path: true, Route: route})
	if err != nil {
		return nil, err
	}
	actx, cancel := context.WithTimeout(ctx, relayReplyTimeout)
	defer cancel()
	if aw, ok := st.(interface{ AwaitReply(context.Context) error }); ok {
		if err := aw.AwaitReply(actx); err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	return &streamConn{Stream: st, local: local, remote: remote}, nil
}

// servePath handles a path stream that arrived on s: as its last hop it
// hands the stream to the session acceptor; otherwise it relays it to the
// next hop if this node allows transit.
func (n *Node) servePath(ctx context.Context, s session.PeerSession, st session.Stream, h frame.StreamHeader) {
	from := s.Peer()
	if len(h.Route) == 0 {
		if _, err := st.Write([]byte{frame.ReplyOK}); err != nil {
			_ = st.Close()
			return
		}
		conn := &streamConn{Stream: st, local: relayAddr(n.Config().Node.ID), remote: relayAddr(relayMetaPrefix + string(from))}
		meta := session.PathMeta{Transport: mesh.TransportRelay, Local: conn.local.String(), Remote: conn.remote.String()}
		if err := n.acceptorHandle(ctx, conn, meta); err != nil {
			n.log.Debug("relayed path rejected", "via", from, "err", err)
		}
		return
	}
	code, next := n.transitCheck(from, h.Route)
	if code != frame.ReplyOK {
		n.log.Debug("relay transit refused", "from", from, "route", h.Route, "code", code)
		_, _ = st.Write([]byte{code})
		_ = st.Close()
		return
	}
	out, err := openPath(ctx, next, h.Route[1:], relayAddr(n.Config().Node.ID), relayAddr(h.Route[0]))
	if err != nil {
		code := frame.ReplyUnreachable
		var re *session.ReplyError
		if errors.As(err, &re) {
			code = re.Code
		}
		_, _ = st.Write([]byte{code})
		_ = st.Close()
		return
	}
	if _, err := st.Write([]byte{frame.ReplyOK}); err != nil {
		_ = st.Close()
		_ = out.Close()
		return
	}
	n.transit.Add(1)
	defer n.transit.Add(-1)
	n.log.Debug("relaying path", "from", from, "to", h.Route[0])
	up, down := core.Pipe(st, out)
	n.transitBytes.Add(uint64(up + down))
}

// transitCheck decides whether a path stream from may be relayed along
// route, and returns the session to its next hop.
func (n *Node) transitCheck(from core.NodeID, route []core.NodeID) (byte, session.PeerSession) {
	cfg := n.Config()
	self := core.NodeID(cfg.Node.ID)
	switch {
	case !cfg.Relay.AllowTransit:
		return frame.ReplyDenied, nil
	case len(route) >= cfg.Relay.MaxHops: // route plus the hop it came on
		return frame.ReplyDenied, nil
	}
	seen := map[core.NodeID]bool{self: true, from: true}
	for _, hop := range route {
		if seen[hop] {
			return frame.ReplyDenied, nil // a loop
		}
		seen[hop] = true
	}
	next := n.directSession(route[0])
	if next == nil {
		return frame.ReplyUnreachable, nil
	}
	return frame.ReplyOK, next
}

func (n *Node) acceptorHandle(ctx context.Context, conn transport.Conn, meta session.PathMeta) error {
	n.mu.RLock()
	acc := n.acceptor
	n.mu.RUnlock()
	return acc.Handle(ctx, conn, meta)
}

// routeOf converts a live path to the route mesh scores diversity on.
func routeOf(m session.PathMeta) mesh.Route {
	if isRelayed(m) {
		return mesh.Route{Transport: m.Transport, Via: core.NodeID(strings.TrimPrefix(m.Remote, relayMetaPrefix))}
	}
	r := mesh.Route{Transport: m.Transport}
	if ap, err := netip.ParseAddrPort(m.Remote); err == nil {
		r.Remote = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	if l, err := netip.ParseAddrPort(m.Local); err == nil {
		r.Local = l.Addr().Unmap()
	}
	return r
}
