package node

import (
	"sort"
	"time"

	"marmot/internal/controller"
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
	Version   int // session protocol: 1 or 2 (ADR-0013)
	Started   time.Time
	Ready     bool
	Streams   int
	BytesSent uint64
	BytesRecv uint64
	// FECData and FECParity are the FEC group on datagram paths (v2);
	// parity 0 means off.
	FECData, FECParity int
	Paths              []PathStatus
}

// PathStatus is one path with the controller's view of it.
type PathStatus struct {
	session.PathInfo
	Scored bool    // the controller has rated the path (v2 only)
	Score  float64 // lower is better, roughly milliseconds
	Loss   float64 // smoothed fraction of packets lost, both directions
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
	n.ctlMu.Lock()
	scores := n.ctl.scores
	n.ctlMu.Unlock()
	for id, l := range n.links {
		if s := l.session(); s != nil && live(s) {
			byPeer[id] = append(byPeer[id], sessionStatus(s, true, scores))
		}
	}
	for _, s := range n.acceptor.Sessions() {
		if live(s) {
			byPeer[s.Peer()] = append(byPeer[s.Peer()], sessionStatus(s, false, scores))
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
		for j := range ps.Sessions {
			ps.BytesSent += ps.Sessions[j].BytesSent
			ps.BytesRecv += ps.Sessions[j].BytesRecv
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
	for i := range ss {
		s := &ss[i]
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

func live(s session.PeerSession) bool {
	select {
	case <-s.Done():
		return false
	default:
		return true
	}
}

func sessionStatus(s session.PeerSession, outbound bool, scores map[string]map[uint64]controller.PathScore) SessionStatus {
	cs := s.Stats()
	key := sessionKey(s)
	paths := make([]PathStatus, 0, len(cs.Paths))
	for i := range cs.Paths {
		p := &cs.Paths[i]
		ps := PathStatus{PathInfo: *p}
		if sc, ok := scores[key][p.ID]; ok {
			ps.Scored, ps.Score, ps.Loss = true, sc.Score, sc.Loss
		}
		paths = append(paths, ps)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].ID < paths[j].ID })
	return SessionStatus{
		ID:        key,
		Outbound:  outbound,
		Version:   s.Version(),
		Started:   s.Started(),
		Ready:     cs.Ready,
		Streams:   s.NumStreams(),
		BytesSent: cs.SentOff,
		BytesRecv: cs.RecvOff,
		FECData:   cs.FECData,
		FECParity: cs.FECParity,
		Paths:     paths,
	}
}
