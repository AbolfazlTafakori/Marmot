package node

import (
	"context"
	"encoding/hex"
	"math"
	"sync"
	"time"

	"marmot/internal/controller"
	"marmot/internal/core"
	"marmot/internal/mesh"
	"marmot/internal/session"
)

// controlEvery is the controller's tick (ADR-0015).
const controlEvery = time.Second

// Candidate preferences handed to the mesh planners: lower is tried first
// among equally diverse routes.
const (
	prefUnmeasured = 100
	prefMaxScore   = 999
	prefDemoted    = 1000
)

// dialLog collects dial and handshake results of direct routes for the
// controller between ticks.
type dialLog struct {
	mu      sync.Mutex
	samples []controller.DialSample
}

const maxDialSamples = 1024

func (d *dialLog) add(c mesh.Candidate, ok bool) {
	if c.Relayed() {
		return
	}
	d.mu.Lock()
	if len(d.samples) < maxDialSamples {
		d.samples = append(d.samples, controller.DialSample{Transport: c.Transport, Remote: c.Remote.Addr(), OK: ok})
	}
	d.mu.Unlock()
}

func (d *dialLog) take() []controller.DialSample {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.samples
	d.samples = nil
	return out
}

// sessionRef is a live session and, for an outbound one, its link.
type sessionRef struct {
	s    session.PeerSession
	link *peerLink
}

// sessionKey names a session for the controller and in status.
func sessionKey(s session.PeerSession) string {
	id := s.ID()
	return hex.EncodeToString(id[:8])
}

// controlState is what the control loop remembers between ticks and what
// status reads. Guarded by Node.ctlMu.
type controlState struct {
	scores  map[string]map[uint64]controller.PathScore // by session key, path id
	health  map[core.NodeID]float64
	fec     map[string]int
	demoted map[string]time.Time
}

// controlLoop runs the adaptive controller until ctx ends.
func (n *Node) controlLoop(ctx context.Context) {
	defer n.wg.Done()
	ctl := controller.New()
	t := time.NewTicker(controlEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n.controlTick(ctl, time.Now())
	}
}

// controlTick gathers one snapshot, asks the controller and applies what
// it decides.
func (n *Node) controlTick(ctl *controller.Controller, now time.Time) {
	refs := n.liveSessions()
	n.mu.RLock()
	fec := n.cfg.FEC
	n.mu.RUnlock()
	in := controller.Input{Now: now, Dials: n.dials.take(),
		FEC: controller.FECPolicy{Mode: fec.Mode, Data: fec.DataShards, MaxParity: fec.MaxParityShards}}
	byKey := map[string]sessionRef{}
	for _, r := range refs {
		if r.s.Version() != 2 {
			continue // v1 has one active path and no FEC: nothing to tune
		}
		key := sessionKey(r.s)
		byKey[key] = r
		paths := r.s.Stats().Paths
		for i := range paths {
			p := &paths[i]
			in.Paths = append(in.Paths, controller.PathSample{
				Session: key, Peer: r.s.Peer(), PathID: p.ID, Transport: p.Meta.Transport, Remote: p.Meta.Remote,
				Relayed: isRelayed(p.Meta), Datagram: p.Datagram, RTT: p.RTT, RTTVar: p.RTTVar,
				Sent: p.PacketsSent, Lost: p.PacketsLost, Recovered: p.Recovered,
				Recv: p.PacketsRecv, RecvSpan: p.RecvSpan,
			})
		}
	}
	out := ctl.Decide(in)

	n.ctlMu.Lock()
	prevFEC, prevDemoted := n.ctl.fec, n.ctl.demoted
	n.ctl = controlState{scores: map[string]map[uint64]controller.PathScore{}, health: out.Health,
		fec: map[string]int{}, demoted: out.Demoted}
	for ref, sc := range out.Scores {
		if n.ctl.scores[ref.Session] == nil {
			n.ctl.scores[ref.Session] = map[uint64]controller.PathScore{}
		}
		n.ctl.scores[ref.Session][ref.PathID] = sc
	}
	for key, d := range out.Sessions {
		n.ctl.fec[key] = d.FECParity
	}
	n.ctlMu.Unlock()

	for key, d := range out.Sessions {
		r := byKey[key]
		r.s.Tune(session.Tuning{Ranks: d.Ranks, FECData: d.FECData, FECParity: d.FECParity})
		if prev, ok := prevFEC[key]; d.FECParity != prev && (ok || d.FECParity > 0) {
			n.log.Info("fec level", "peer", r.s.Peer(), "session", key, "parity", d.FECParity, "data", d.FECData)
		}
	}
	for _, rp := range out.Replace {
		if r := byKey[rp.Session]; r.link != nil {
			n.log.Info("replacing lossy path", "peer", rp.Peer, "path", rp.PathID)
			r.link.requestReplace(rp.PathID)
		}
	}
	for t, until := range out.Demoted {
		if _, was := prevDemoted[t]; !was {
			n.log.Warn("transport demoted: it fails on several peer addresses", "transport", t, "until", until)
		}
	}
	for t := range prevDemoted {
		if _, still := out.Demoted[t]; !still {
			n.log.Info("transport demotion lifted", "transport", t)
		}
	}
	pref := preference(now, out.Demoted, routeScores(in.Paths, out.Scores))
	n.mu.RLock()
	for _, l := range n.links {
		l.setPreference(pref)
	}
	n.mu.RUnlock()
}

// liveSessions lists every live session: outbound ones with their links,
// then inbound ones.
func (n *Node) liveSessions() []sessionRef {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.running {
		return nil
	}
	var out []sessionRef
	for _, l := range n.links {
		if s := l.session(); s != nil && live(s) {
			out = append(out, sessionRef{s: s, link: l})
		}
	}
	for _, s := range n.acceptor.Sessions() {
		if live(s) {
			out = append(out, sessionRef{s: s})
		}
	}
	return out
}

// routeScores maps transport|remote of each direct path to its best score.
func routeScores(paths []controller.PathSample, scores map[controller.PathRef]controller.PathScore) map[string]float64 {
	out := map[string]float64{}
	for i := range paths {
		p := &paths[i]
		if p.Relayed {
			continue
		}
		sc, ok := scores[controller.PathRef{Session: p.Session, Peer: p.Peer, PathID: p.PathID}]
		if !ok {
			continue
		}
		k := p.Transport + "|" + p.Remote
		if prev, seen := out[k]; !seen || sc.Score < prev {
			out[k] = sc.Score
		}
	}
	return out
}

// preference ranks candidates for the planners: by the measured score of
// the same route, unmeasured ones in the middle, a demoted transport
// after all of them.
func preference(now time.Time, demoted map[string]time.Time, scores map[string]float64) func(mesh.Candidate) int {
	return func(c mesh.Candidate) int {
		p := prefUnmeasured
		if s, ok := scores[c.Transport+"|"+c.Remote.String()]; ok {
			p = int(math.Min(s, prefMaxScore))
		}
		if until, ok := demoted[c.Transport]; ok && now.Before(until) {
			p += prefDemoted
		}
		return p
	}
}

// healthWeight scales a peer's configured weight by the controller's
// health factor; weights are multiplied by 10 to keep the scale fine.
func healthWeight(weight int, health float64, known bool) int {
	if !known {
		health = 1
	}
	return max(1, int(math.Round(float64(weight)*health*10)))
}
