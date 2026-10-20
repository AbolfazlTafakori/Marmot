package node

import (
	"encoding/hex"
	"sort"
	"time"

	"marmot/internal/core"
	"marmot/internal/forwarder"
	"marmot/internal/session"
	"marmot/internal/steering"
)

// Peer states, as in the API's PeerHealth schema.
const (
	PeerUp       = "up"
	PeerDegraded = "degraded"
	PeerRelayed  = "relayed" // up, but only through a relay node
	PeerDown     = "down"
)

// Status is a point-in-time view of the node.
type Status struct {
	NodeID    string
	Role      string
	Version   string
	Running   bool
	Started   time.Time
	Peers     []PeerStatus
	Ports     []steering.PortStatus
	Listeners []ListenerStatus
	Forwarder forwarder.Stats
	Transit   TransitStatus
}

// TransitStatus counts relayed paths passing through this node.
type TransitStatus struct {
	Active int64
	Bytes  uint64 // of relayed paths that have ended
}

// PeerStatus is the health of one configured peer. BytesSent and
// BytesRecv are totals since the node started, over all sessions.
type PeerStatus struct {
	ID        core.NodeID
	Weight    int
	State     string
	Sessions  []SessionStatus
	BytesSent uint64
	BytesRecv uint64
}

// SessionStatus describes one session with a peer.
type SessionStatus struct {
	ID        string
	Outbound  bool
	Started   time.Time
	Ready     bool
	Streams   int
	BytesSent uint64
	BytesRecv uint64
	Paths     []session.PathInfo
}

// ListenerStatus is one inter-node listener.
type ListenerStatus struct {
	Transport string
	Addr      string
}

// Snapshot returns the current status.
func (n *Node) Snapshot() Status {
	n.mu.RLock()
	defer n.mu.RUnlock()
	st := Status{NodeID: n.cfg.Node.ID, Role: n.cfg.Node.Role, Version: n.version, Running: n.running, Started: n.started}
	if !n.running {
		return st
	}
	byPeer := map[core.NodeID][]SessionStatus{}
	// Ended sessions are left out: their bytes move to the closed totals.
	for id, l := range n.links {
		if s := l.session(); s != nil && live(s) {
			byPeer[id] = append(byPeer[id], sessionStatus(s, true))
		}
	}
	for _, s := range n.acceptor.Sessions() {
		if live(s) {
			byPeer[s.Peer()] = append(byPeer[s.Peer()], sessionStatus(s, false))
		}
	}
	n.totalsMu.Lock()
	closed := make(map[core.NodeID]byteTotals, len(n.closed))
	for k, v := range n.closed {
		closed[k] = v
	}
	n.totalsMu.Unlock()
	for i := range n.cfg.Peers {
		p := &n.cfg.Peers[i]
		id := core.NodeID(p.ID)
		ps := PeerStatus{ID: id, Weight: p.Weight, State: PeerDown, Sessions: byPeer[id],
			BytesSent: closed[id].sent, BytesRecv: closed[id].recv}
		for _, s := range ps.Sessions {
			ps.BytesSent += s.BytesSent
			ps.BytesRecv += s.BytesRecv
		}
		ps.State = peerState(ps.Sessions)
		st.Peers = append(st.Peers, ps)
	}
	st.Ports = n.steering.Ports()
	for _, l := range n.listeners {
		st.Listeners = append(st.Listeners, ListenerStatus{Transport: l.transport, Addr: l.addr()})
	}
	sort.Slice(st.Listeners, func(i, j int) bool { return st.Listeners[i].Addr < st.Listeners[j].Addr })
	st.Forwarder = n.forwarder.Stats()
	st.Transit = TransitStatus{Active: n.transit.Load(), Bytes: n.transitBytes.Load()}
	return st
}

// peerState is up when a ready session runs on a direct path, relayed when
// ready sessions run only through relays, degraded when no session is
// ready, and down without sessions.
func peerState(ss []SessionStatus) string {
	state := PeerDown
	for _, s := range ss {
		switch {
		case !s.Ready:
			if state == PeerDown {
				state = PeerDegraded
			}
		case s.relayed():
			state = PeerRelayed
		default:
			return PeerUp
		}
	}
	return state
}

func (s *SessionStatus) relayed() bool {
	for i := range s.Paths {
		if s.Paths[i].Active {
			return isRelayed(s.Paths[i].Meta)
		}
	}
	return false
}

func live(s *session.MuxSession) bool {
	select {
	case <-s.Done():
		return false
	default:
		return true
	}
}

func sessionStatus(s *session.MuxSession, outbound bool) SessionStatus {
	cs := s.Stats()
	id := s.ID()
	paths := cs.Paths
	sort.Slice(paths, func(i, j int) bool { return paths[i].ID < paths[j].ID })
	return SessionStatus{
		ID:        hex.EncodeToString(id[:8]),
		Outbound:  outbound,
		Started:   s.Started(),
		Ready:     cs.Ready,
		Streams:   s.NumStreams(),
		BytesSent: cs.SentOff,
		BytesRecv: cs.RecvOff,
		Paths:     paths,
	}
}
