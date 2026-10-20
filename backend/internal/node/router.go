package node

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/session"
	"marmot/internal/steering"
)

// ErrNoRoute means no allowed peer has a live session.
var ErrNoRoute = errors.New("node: no live session to any allowed peer")

type routeCandidate struct {
	s      *session.MuxSession
	weight int
}

// Open implements steering.Opener: it picks a live session to one of the
// rule's peers, weighted by peer weight, and opens the stream there. If
// opening fails it tries the next one. The weighted choice is the Phase 1
// stand-in for the scheduler.
func (n *Node) Open(ctx context.Context, rule steering.Rule, h frame.StreamHeader) (session.Stream, error) {
	cands := n.routeCandidates(rule.Peers, h.Proto)
	lastErr := ErrNoRoute
	for len(cands) > 0 {
		i := weightedPick(cands)
		c := cands[i]
		cands = append(cands[:i], cands[i+1:]...)
		st, err := c.s.OpenStream(ctx, h)
		if err == nil {
			return st, nil
		}
		lastErr = fmt.Errorf("peer %s: %w", c.s.Peer(), err)
	}
	return nil, lastErr
}

// routeCandidates returns one session per allowed peer: the outbound one
// when it is up, else the newest inbound one (the peer dialed us).
func (n *Node) routeCandidates(allowed []core.NodeID, proto core.Proto) []routeCandidate {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.running {
		return nil
	}
	peers := allowed
	if len(peers) == 0 {
		peers = make([]core.NodeID, 0, len(n.weights))
		for id := range n.weights {
			peers = append(peers, id)
		}
	}
	var inbound map[core.NodeID]*session.MuxSession
	out := make([]routeCandidate, 0, len(peers))
	for _, id := range peers {
		w, ok := n.weights[id]
		if !ok {
			continue
		}
		var s *session.MuxSession
		if l := n.links[id]; l != nil {
			s = l.session()
		}
		if s == nil {
			if inbound == nil {
				inbound = newestInbound(n.acceptor.Sessions())
			}
			s = inbound[id]
		}
		if s == nil || (proto == core.ProtoUDP && s.Caps()&crypto.CapUDP == 0) {
			continue
		}
		out = append(out, routeCandidate{s: s, weight: w})
	}
	return out
}

func newestInbound(all []*session.MuxSession) map[core.NodeID]*session.MuxSession {
	m := make(map[core.NodeID]*session.MuxSession, len(all))
	for _, s := range all {
		if cur := m[s.Peer()]; cur == nil || s.Started().After(cur.Started()) {
			m[s.Peer()] = s
		}
	}
	return m
}

func weightedPick(cands []routeCandidate) int {
	total := 0
	for _, c := range cands {
		total += c.weight
	}
	r := rand.IntN(total) //nolint:gosec // load spreading, not a secret
	for i, c := range cands {
		if r < c.weight {
			return i
		}
		r -= c.weight
	}
	return len(cands) - 1
}
