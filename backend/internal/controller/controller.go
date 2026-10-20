// Package controller is the adaptive controller (ARCHITECTURE §11,
// ADR-0015). It observes path and dial metrics and decides path ranks,
// FEC parity, paths to replace, transports to demote and peer health. It
// never touches a socket: Decide is pure apart from the controller's own
// memory, so every decision is tested from recorded inputs.
package controller

import (
	"math"
	"net/netip"
	"time"

	"marmot/internal/core"
)

// Tuning constants (ADR-0015).
const (
	lossAlpha       = 0.3 // EWMA weight of a tick's loss
	relayPenaltyMs  = 50.0
	lossyPenaltyMs  = 200.0
	unknownScore    = 1e6
	switchRatio     = 0.8 // a challenger must be 20 % better
	switchTicks     = 3
	replaceLoss     = 0.25
	replaceTicks    = 5
	fecHold         = 10 * time.Second
	dialWindow      = 60 * time.Second
	demoteFailures  = 3
	demoteAddresses = 2
	demoteFor       = 5 * time.Minute
	demoteSpread    = 5 * time.Second // failures must span this long
	minHealth       = 0.1
)

// fecThresholds are the loss rates that each add one parity symbol.
var fecThresholds = [...]float64{0.005, 0.02, 0.05, 0.10}

// PathSample is what the node reports about one path of a live session.
// Counters are cumulative; the controller works out the deltas.
type PathSample struct {
	Session   string // identifies the session among all peers
	Peer      core.NodeID
	PathID    uint64
	Transport string
	Remote    string
	Relayed   bool
	Datagram  bool
	RTT       time.Duration // 0 = not measured yet
	RTTVar    time.Duration
	Sent      uint64 // packets sent
	Lost      uint64 // sent packets lost and not rebuilt by FEC
	Recovered uint64 // received packets rebuilt by FEC
	Recv      uint64 // packets received from the wire
	RecvSpan  uint64 // packet numbers the peer used
}

// DialSample is one dial or handshake attempt of a direct route.
type DialSample struct {
	Transport string
	Remote    netip.Addr
	OK        bool
}

// FECPolicy is the configured FEC mode (config [fec]).
type FECPolicy struct {
	Mode      string // off | fixed | adaptive
	Data      int
	MaxParity int
}

// Input is one tick's snapshot.
type Input struct {
	Now   time.Time
	Paths []PathSample
	Dials []DialSample // since the previous tick
	FEC   FECPolicy
}

// SessionDecision is applied to one session.
type SessionDecision struct {
	Ranks     map[uint64]int
	FECData   int
	FECParity int
}

// PathRef names a path to replace.
type PathRef struct {
	Session string
	Peer    core.NodeID
	PathID  uint64
}

// PathScore is reported for status.
type PathScore struct {
	Score float64
	Loss  float64
}

// Output is what the node applies.
type Output struct {
	Sessions map[string]SessionDecision
	Replace  []PathRef
	// Demoted maps a transport to the end of its demotion.
	Demoted map[string]time.Time
	// Health scales each peer's weight for tunneled streams (0.1–1).
	Health map[core.NodeID]float64
	Scores map[PathRef]PathScore
}

type pathKey struct {
	session string
	id      uint64
}

type pathMem struct {
	sent, lost     uint64
	recv, recvSpan uint64
	loss           float64
	lossyTicks     int
	seen           bool // counters initialised
}

type sessionMem struct {
	first      uint64 // current first-ranked path, 0 = none yet
	challenger uint64
	streak     int
	fec        int
	fecSince   time.Time // last time the target was at or above fec
}

type dialRecord struct {
	at     time.Time
	remote netip.Addr
	ok     bool
}

// Controller keeps the memory Decide needs between ticks. It is not safe
// for concurrent use; the node calls it from one goroutine.
type Controller struct {
	paths    map[pathKey]*pathMem
	sessions map[string]*sessionMem
	dials    map[string][]dialRecord
	demoted  map[string]time.Time
}

// New returns a controller with empty memory.
func New() *Controller {
	return &Controller{
		paths:    map[pathKey]*pathMem{},
		sessions: map[string]*sessionMem{},
		dials:    map[string][]dialRecord{},
		demoted:  map[string]time.Time{},
	}
}

// Decide takes one tick's snapshot and returns the decisions.
func (c *Controller) Decide(in Input) Output {
	out := Output{
		Sessions: map[string]SessionDecision{},
		Demoted:  map[string]time.Time{},
		Health:   map[core.NodeID]float64{},
		Scores:   map[PathRef]PathScore{},
	}
	bySession := map[string][]PathSample{}
	live := map[pathKey]bool{}
	scores := map[pathKey]float64{}
	for i := range in.Paths {
		p := &in.Paths[i]
		k := pathKey{p.Session, p.PathID}
		live[k] = true
		m := c.observe(k, p)
		scores[k] = score(p, m)
		bySession[p.Session] = append(bySession[p.Session], *p)
		ref := PathRef{Session: p.Session, Peer: p.Peer, PathID: p.PathID}
		out.Scores[ref] = PathScore{Score: scores[k], Loss: m.loss}
		if m.loss > replaceLoss {
			m.lossyTicks++
			if m.lossyTicks >= replaceTicks {
				out.Replace = append(out.Replace, ref)
				m.lossyTicks = 0
			}
		} else {
			m.lossyTicks = 0
		}
	}
	for k := range c.paths {
		if !live[k] {
			delete(c.paths, k)
		}
	}
	for id := range c.sessions {
		if _, ok := bySession[id]; !ok {
			delete(c.sessions, id)
		}
	}
	for id, paths := range bySession {
		mem := c.sessions[id]
		if mem == nil {
			mem = &sessionMem{}
			c.sessions[id] = mem
		}
		out.Sessions[id] = SessionDecision{
			Ranks:     c.rank(mem, id, paths, scores),
			FECData:   in.FEC.Data,
			FECParity: c.fec(mem, in, paths),
		}
	}
	out.Health = c.health(in.Paths)
	c.dialsTick(in)
	for t, until := range c.demoted {
		out.Demoted[t] = until
	}
	return out
}

// observe folds the path's counters into its loss EWMA. A tick's loss is
// the larger of two rates: sent packets lost and not rebuilt, and the raw
// loss of the incoming direction (packet numbers that never arrived from
// the wire). The second does not fall when our FEC repairs losses, so FEC
// sizing does not oscillate; it assumes loss is about the same both ways.
func (c *Controller) observe(k pathKey, p *PathSample) *pathMem {
	m := c.paths[k]
	if m == nil {
		m = &pathMem{}
		c.paths[k] = m
	}
	if m.seen && p.Sent >= m.sent && p.Lost >= m.lost && p.Recv >= m.recv && p.RecvSpan >= m.recvSpan {
		var rate float64
		counted := false
		if sent := p.Sent - m.sent; sent > 0 {
			rate = float64(p.Lost-m.lost) / float64(sent)
			counted = true
		}
		if span := p.RecvSpan - m.recvSpan; span > 0 {
			got := min(p.Recv-m.recv, span)
			rate = math.Max(rate, 1-float64(got)/float64(span))
			counted = true
		}
		if counted {
			m.loss = (1-lossAlpha)*m.loss + lossAlpha*math.Min(rate, 1)
		}
	}
	m.sent, m.lost, m.recv, m.recvSpan, m.seen = p.Sent, p.Lost, p.Recv, p.RecvSpan, true
	return m
}

// score is lower for a better path (ADR-0015 §3).
func score(p *PathSample, m *pathMem) float64 {
	if p.RTT <= 0 {
		return unknownScore
	}
	rtt := float64(p.RTT) / float64(time.Millisecond)
	v := float64(p.RTTVar) / float64(time.Millisecond)
	s := rtt*(1+8*m.loss) + 2*v
	if p.Relayed {
		s += relayPenaltyMs
	}
	if m.lossyTicks > 0 {
		s += lossyPenaltyMs
	}
	return s
}
