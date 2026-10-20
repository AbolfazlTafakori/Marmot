package controller

import (
	"net/netip"
	"testing"
	"time"
)

// sim drives a controller tick by tick with paths whose counters advance
// as a given loss and RTT say.
type sim struct {
	c     *Controller
	now   time.Time
	paths map[uint64]*PathSample
	fec   FECPolicy
}

func newSim() *sim {
	return &sim{c: New(), now: time.Unix(1_000_000, 0), paths: map[uint64]*PathSample{},
		fec: FECPolicy{Mode: "adaptive", Data: 4, MaxParity: 3}}
}

func (s *sim) add(id uint64, rtt time.Duration, datagram bool) *PathSample {
	p := &PathSample{Session: "s1", Peer: "kharej", PathID: id, Transport: "quic",
		Remote: "198.51.100.1:443", RTT: rtt, RTTVar: rtt / 10, Datagram: datagram}
	s.paths[id] = p
	return p
}

// tick advances every path by 1,000 packets each way at its loss rate.
func (s *sim) tick(loss map[uint64]float64, dials ...DialSample) Output {
	s.now = s.now.Add(time.Second)
	in := Input{Now: s.now, Dials: dials, FEC: s.fec}
	for id, p := range s.paths {
		l := uint64(loss[id] * 1000)
		p.Sent += 1000
		p.Lost += l
		p.RecvSpan += 1000
		p.Recv += 1000 - l
		in.Paths = append(in.Paths, *p)
	}
	return s.c.Decide(in)
}

func first(d SessionDecision) uint64 {
	for id, r := range d.Ranks {
		if r == 0 {
			return id
		}
	}
	return 0
}

func TestRankPrefersLowScore(t *testing.T) {
	s := newSim()
	s.add(1, 80*time.Millisecond, false)
	s.add(2, 30*time.Millisecond, false)
	out := s.tick(nil)
	d := out.Sessions["s1"]
	if first(d) != 2 || d.Ranks[1] != 1 {
		t.Fatalf("ranks %v", d.Ranks)
	}
}

func TestRankHysteresis(t *testing.T) {
	s := newSim()
	a := s.add(1, 50*time.Millisecond, false)
	b := s.add(2, 60*time.Millisecond, false)
	if f := first(s.tick(nil).Sessions["s1"]); f != 1 {
		t.Fatalf("first %d", f)
	}
	// 10 % better is not enough.
	b.RTT = 45 * time.Millisecond
	for range 5 {
		if f := first(s.tick(nil).Sessions["s1"]); f != 1 {
			t.Fatal("switched for a 10 % gain")
		}
	}
	// Clearly better, but it must hold for three ticks.
	b.RTT = 20 * time.Millisecond
	for i := range 3 {
		f := first(s.tick(nil).Sessions["s1"])
		if want := uint64(1); i < 2 && f != want {
			t.Fatalf("tick %d: switched early", i)
		}
		if i == 2 && f != 2 {
			t.Fatalf("tick %d: did not switch", i)
		}
	}
	// A flapping challenger never wins.
	a.RTT = 10 * time.Millisecond
	for i := range 6 {
		if i%2 == 0 {
			a.RTT = 10 * time.Millisecond
		} else {
			a.RTT = 50 * time.Millisecond
		}
		if f := first(s.tick(nil).Sessions["s1"]); f != 2 {
			t.Fatalf("tick %d: flapping path took over", i)
		}
	}
}

func TestRankLossAndRelay(t *testing.T) {
	s := newSim()
	s.add(1, 40*time.Millisecond, false)
	relay := s.add(2, 20*time.Millisecond, false)
	relay.Relayed = true
	if f := first(s.tick(nil).Sessions["s1"]); f != 1 {
		t.Fatal("relayed path ranked first despite its penalty")
	}
	s2 := newSim()
	s2.add(1, 40*time.Millisecond, true)
	s2.add(2, 60*time.Millisecond, true)
	var out Output
	for range 8 {
		out = s2.tick(map[uint64]float64{1: 0.2})
	}
	if f := first(out.Sessions["s1"]); f != 2 {
		t.Fatalf("lossy path still first: %v", out.Sessions["s1"].Ranks)
	}
}

func TestUnknownRTTRanksLast(t *testing.T) {
	s := newSim()
	s.add(1, 0, false)
	s.add(2, 300*time.Millisecond, false)
	if f := first(s.tick(nil).Sessions["s1"]); f != 2 {
		t.Fatal("unmeasured path ranked first")
	}
}

func TestFECAdaptive(t *testing.T) {
	s := newSim()
	s.add(1, 50*time.Millisecond, true)
	if m := s.tick(nil).Sessions["s1"].FECParity; m != 0 {
		t.Fatalf("parity %d on a clean path", m)
	}
	var m int
	for range 6 {
		m = s.tick(map[uint64]float64{1: 0.03}).Sessions["s1"].FECParity
	}
	if m != 2 {
		t.Fatalf("parity %d at 3 %% loss, want 2", m)
	}
	for range 10 {
		m = s.tick(map[uint64]float64{1: 0.3}).Sessions["s1"].FECParity
	}
	if m != 3 {
		t.Fatalf("parity %d at 30 %% loss, want the cap 3", m)
	}
	// Loss ends: the level holds for fecHold, then drops.
	var levels []int
	for range 25 {
		levels = append(levels, s.tick(nil).Sessions["s1"].FECParity)
	}
	if levels[0] != 3 || levels[5] != 3 {
		t.Fatalf("lowered too soon: %v", levels)
	}
	if levels[len(levels)-1] != 0 {
		t.Fatalf("never lowered: %v", levels)
	}
}

// The incoming direction's raw loss keeps FEC on even when FEC repairs
// every loss of the outgoing direction, so the level does not oscillate.
func TestFECNotFooledByItsOwnRepairs(t *testing.T) {
	s := newSim()
	p := s.add(1, 50*time.Millisecond, true)
	var m int
	for range 10 {
		s.now = s.now.Add(time.Second)
		p.Sent += 1000 // nothing reported lost: FEC rebuilt it all
		p.RecvSpan += 1000
		p.Recv += 960 // but 4 % of the incoming packets never arrived
		m = s.c.Decide(Input{Now: s.now, Paths: []PathSample{*p}, FEC: s.fec}).Sessions["s1"].FECParity
	}
	if m != 2 {
		t.Fatalf("parity %d, want 2 from the incoming loss", m)
	}
}

func TestFECModes(t *testing.T) {
	s := newSim()
	s.add(1, 50*time.Millisecond, true)
	s.fec.Mode = "fixed"
	if d := s.tick(nil).Sessions["s1"]; d.FECParity != 3 || d.FECData != 4 {
		t.Fatalf("fixed: %+v", d)
	}
	s.fec.Mode = "off"
	if m := s.tick(map[uint64]float64{1: 0.5}).Sessions["s1"].FECParity; m != 0 {
		t.Fatalf("off: parity %d", m)
	}
	s2 := newSim()
	s2.add(1, 50*time.Millisecond, false) // no datagram path: FEC cannot help
	var m int
	for range 6 {
		m = s2.tick(map[uint64]float64{1: 0.1}).Sessions["s1"].FECParity
	}
	if m != 0 {
		t.Fatalf("parity %d without datagram paths", m)
	}
}

func TestReplaceLossyPath(t *testing.T) {
	s := newSim()
	s.add(1, 50*time.Millisecond, true)
	s.add(2, 50*time.Millisecond, true)
	var replaced []PathRef
	for range 12 {
		replaced = append(replaced, s.tick(map[uint64]float64{1: 0.5}).Replace...)
	}
	if len(replaced) == 0 || replaced[0].PathID != 1 || replaced[0].Peer != "kharej" {
		t.Fatalf("replace %v", replaced)
	}
	for _, r := range replaced {
		if r.PathID != 1 {
			t.Fatalf("healthy path replaced: %v", r)
		}
	}
	if len(replaced) > 2 {
		t.Fatalf("asked %d times in 12 ticks; once per %d ticks at most", len(replaced), replaceTicks)
	}
}

func dial(tr, addr string, ok bool) DialSample {
	return DialSample{Transport: tr, Remote: netip.MustParseAddr(addr), OK: ok}
}

func TestDemotion(t *testing.T) {
	s := newSim()
	// Failures on one address only are a route problem, not a block.
	out := s.tick(nil, dial("tls", "198.51.100.1", false), dial("tls", "198.51.100.1", false), dial("tls", "198.51.100.1", false))
	if _, ok := out.Demoted["tls"]; ok {
		t.Fatal("demoted after failures on one address")
	}
	// A burst within a moment (peers still starting) is not a block.
	out = s.tick(nil, dial("tls", "198.51.100.2", false))
	if _, ok := out.Demoted["tls"]; ok {
		t.Fatal("demoted for failures within one second")
	}
	s.now = s.now.Add(demoteSpread)
	out = s.tick(nil, dial("tls", "198.51.100.2", false))
	until, ok := out.Demoted["tls"]
	if !ok || until.Sub(s.now) != demoteFor {
		t.Fatalf("not demoted for %v: %v", demoteFor, out.Demoted)
	}
	if _, ok := out.Demoted["quic"]; ok {
		t.Fatal("other transport demoted")
	}
	// A success lifts the demotion at once.
	out = s.tick(nil, dial("tls", "198.51.100.3", true))
	if _, ok := out.Demoted["tls"]; ok {
		t.Fatal("still demoted after a success")
	}
	// A success inside the window prevents demotion.
	s2 := newSim()
	s2.tick(nil, dial("ws", "198.51.100.1", true))
	out = s2.tick(nil, dial("ws", "198.51.100.1", false), dial("ws", "198.51.100.2", false), dial("ws", "198.51.100.3", false))
	if _, ok := out.Demoted["ws"]; ok {
		t.Fatal("demoted despite a recent success")
	}
	// The demotion expires.
	s3 := newSim()
	s3.tick(nil, dial("grpc", "198.51.100.1", false), dial("grpc", "198.51.100.2", false))
	s3.now = s3.now.Add(demoteSpread)
	if out := s3.tick(nil, dial("grpc", "198.51.100.3", false)); len(out.Demoted) != 1 {
		t.Fatalf("not demoted: %v", out.Demoted)
	}
	s3.now = s3.now.Add(demoteFor)
	if out := s3.tick(nil); len(out.Demoted) != 0 {
		t.Fatalf("demotion outlived its time: %v", out.Demoted)
	}
}

func TestHealth(t *testing.T) {
	s := newSim()
	s.add(1, 50*time.Millisecond, true)
	var out Output
	for range 20 {
		out = s.tick(map[uint64]float64{1: 0.1})
	}
	if h := out.Health["kharej"]; h < 0.79 || h > 0.81 {
		t.Fatalf("health %v at 10 %% loss, want 0.8", h)
	}
	s2 := newSim()
	p := s2.add(1, 50*time.Millisecond, false)
	p.Relayed = true
	if h := s2.tick(nil).Health["kharej"]; h != 0.5 {
		t.Fatalf("relayed-only health %v", h)
	}
	for range 20 {
		out = s2.tick(map[uint64]float64{1: 0.9})
	}
	if h := out.Health["kharej"]; h != minHealth {
		t.Fatalf("health %v, want the floor", h)
	}
}

func TestForgetsGoneSessionsAndPaths(t *testing.T) {
	s := newSim()
	s.add(1, 50*time.Millisecond, false)
	s.add(2, 60*time.Millisecond, false)
	s.tick(nil)
	delete(s.paths, 1)
	out := s.tick(nil)
	if len(s.c.paths) != 1 || first(out.Sessions["s1"]) != 2 {
		t.Fatalf("paths %d, first %d", len(s.c.paths), first(out.Sessions["s1"]))
	}
	delete(s.paths, 2)
	out = s.tick(nil)
	if len(s.c.sessions) != 0 || len(out.Sessions) != 0 {
		t.Fatal("gone session kept")
	}
}
