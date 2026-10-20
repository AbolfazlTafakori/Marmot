package node

import (
	"context"
	"errors"
	"fmt"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/scheduler"
	"marmot/internal/session"
	"marmot/internal/steering"
)

// ErrNoRoute means no allowed peer has a live session.
var ErrNoRoute = errors.New("node: no live session to any allowed peer")

// Open implements steering.Opener: the scheduler orders the rule's peers
// that have a live session, and the stream opens on the first that takes
// it. Tunneled streams spread by weight scaled by the controller's health
// factor (ADR-0015).
func (n *Node) Open(ctx context.Context, rule steering.Rule, h frame.StreamHeader) (session.Stream, error) {
	lastErr := ErrNoRoute
	for _, s := range n.route(rule.Peers, h.Proto, h.Class) {
		st, err := s.OpenStream(ctx, h)
		if err == nil {
			return st, nil
		}
		lastErr = fmt.Errorf("peer %s: %w", s.Peer(), err)
	}
	return nil, lastErr
}

// route returns one session per allowed peer that can carry proto, in the
// order the scheduler picks for class.
func (n *Node) route(allowed []core.NodeID, proto core.Proto, class core.Class) []session.PeerSession {
	n.mu.RLock()
	if !n.running {
		n.mu.RUnlock()
		return nil
	}
	peers := allowed
	if len(peers) == 0 {
		peers = make([]core.NodeID, 0, len(n.weights))
		for id := range n.weights {
			peers = append(peers, id)
		}
	}
	byPeer := map[core.NodeID][]session.PeerSession{}
	for _, id := range peers {
		if _, ok := n.weights[id]; !ok {
			continue
		}
		if l := n.links[id]; l != nil {
			if s := l.session(); s != nil {
				byPeer[id] = append(byPeer[id], s)
			}
		}
	}
	for _, s := range n.acceptor.Sessions() {
		if ss, ok := byPeer[s.Peer()]; ok || n.allowed(peers, s.Peer()) {
			byPeer[s.Peer()] = append(ss, s)
		}
	}
	weights := n.weights
	pick := n.picker
	n.mu.RUnlock()
	n.ctlMu.Lock()
	health := n.ctl.health
	n.ctlMu.Unlock()

	sessions := make([]session.PeerSession, 0, len(byPeer))
	cands := make([]scheduler.Candidate, 0, len(byPeer))
	for id, ss := range byPeer {
		s, c, ok := bestSession(ss, proto)
		if !ok {
			continue
		}
		h, known := health[id]
		c.Peer, c.Weight = id, healthWeight(weights[id], h, known)
		sessions = append(sessions, s)
		cands = append(cands, c)
	}
	out := make([]session.PeerSession, 0, len(sessions))
	for _, i := range pick.Order(class, cands) {
		out = append(out, sessions[i])
	}
	return out
}

func (n *Node) allowed(peers []core.NodeID, id core.NodeID) bool {
	if _, ok := n.weights[id]; !ok {
		return false
	}
	for _, p := range peers {
		if p == id {
			return true
		}
	}
	return false
}

// bestSession picks the session to a peer that should carry a stream: a
// ready one on a direct path, else a ready relayed one, else any live one
// (it may recover within resume_timeout); the outbound session, listed
// first, wins ties, then the newest inbound.
func bestSession(ss []session.PeerSession, proto core.Proto) (session.PeerSession, scheduler.Candidate, bool) {
	var (
		best     session.PeerSession
		bestCand scheduler.Candidate
		bestRank = -1
	)
	for _, s := range ss {
		if !live(s) || (proto == core.ProtoUDP && s.Caps()&crypto.CapUDP == 0) {
			continue
		}
		st := s.Stats()
		c := scheduler.Candidate{Streams: s.NumStreams()}
		rank := 0
		if p, ok := activePath(st); ok && st.Ready {
			c.RTT, c.Relayed = p.RTT, isRelayed(p.Meta)
			rank = 1
			if !c.Relayed {
				rank = 2
			}
		}
		if rank > bestRank || (rank == bestRank && best.Role() != session.Initiator && s.Started().After(best.Started())) {
			best, bestCand, bestRank = s, c, rank
		}
	}
	if best == nil {
		return nil, scheduler.Candidate{}, false
	}
	if bestRank == 0 {
		bestCand.Relayed = true // not ready: try it after every ready session
	}
	return best, bestCand, true
}
