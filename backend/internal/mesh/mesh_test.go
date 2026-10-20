package mesh

import (
	"net/netip"
	"testing"
	"time"

	"marmot/internal/core"
)

func known(string) bool { return true }

func TestExpandFamiliesAndLocals(t *testing.T) {
	p := PeerSpec{
		Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		Endpoints: []Endpoint{
			{Transport: "tcp", Ports: []uint16{443, 8443}},
			{Transport: "tls", Ports: []uint16{443}, Family: FamilyIPv6},
			{Transport: "quic", Ports: []uint16{443}},
		},
	}
	locals := Locals{V4: []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")}}
	got, skipped := Expand(p, locals, func(n string) bool { return n != "quic" })
	if len(skipped) != 1 || skipped[0] != "quic" {
		t.Fatalf("skipped = %v", skipped)
	}
	// tcp: v4 2 ports × 2 locals = 4, v6 2 ports × OS source = 2; tls: v6 only = 1.
	if len(got) != 7 {
		t.Fatalf("got %d candidates: %v", len(got), got)
	}
	for _, c := range got {
		if c.Remote.Addr().Is4() && !c.Local.IsValid() {
			t.Errorf("IPv4 candidate without a local address: %v", c)
		}
		if c.Remote.Addr().Is6() && c.Local.IsValid() {
			t.Errorf("IPv6 candidate with an IPv4 local: %v", c)
		}
		if c.Transport == "tls" && c.Remote.Addr().Is4() {
			t.Errorf("family filter ignored: %v", c)
		}
	}
}

func TestExpandPortRangeSample(t *testing.T) {
	p := PeerSpec{
		Addrs:     []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Endpoints: []Endpoint{{Transport: "tcp", PortRange: [2]uint16{40000, 50000}}},
	}
	got, _ := Expand(p, Locals{}, known)
	if len(got) != rangeSample {
		t.Fatalf("got %d candidates, want %d", len(got), rangeSample)
	}
	seen := map[uint16]bool{}
	for _, c := range got {
		port := c.Remote.Port()
		if port < 40000 || port > 50000 || seen[port] {
			t.Fatalf("bad or repeated port %d", port)
		}
		seen[port] = true
	}
	small, _ := Expand(PeerSpec{Addrs: p.Addrs,
		Endpoints: []Endpoint{{Transport: "tcp", PortRange: [2]uint16{10, 11}}}}, Locals{}, known)
	if len(small) != 2 {
		t.Fatalf("small range gave %d candidates", len(small))
	}
}

func cand(tr, local, remote string) Candidate {
	c := Candidate{Transport: tr, Remote: netip.MustParseAddrPort(remote)}
	if local != "" {
		c.Local = netip.MustParseAddr(local)
	}
	return c
}

func TestPlannerPrefersDiversity(t *testing.T) {
	cands := []Candidate{
		cand("tcp", "198.51.100.1", "192.0.2.1:443"),
		cand("tls", "198.51.100.1", "192.0.2.1:443"),
		cand("tcp", "198.51.100.1", "192.0.2.2:443"),
		cand("tcp", "", "[2001:db8::1]:443"),
	}
	p := NewPlanner(cands, nil)
	inUse := []Route{cands[0].Route()}
	c, _, ok := p.Next(inUse, Direct)
	if !ok || c.Key() != cands[3].Key() {
		t.Fatalf("first standby = %v, want the IPv6 one", c)
	}
	inUse = append(inUse, c.Route())
	c, _, ok = p.Next(inUse, Direct)
	if !ok || c.Key() != cands[2].Key() {
		t.Fatalf("second standby = %v, want the other peer address", c)
	}
	inUse = append(inUse, c.Route())
	c, _, ok = p.Next(inUse, Direct)
	if !ok || c.Key() != cands[1].Key() {
		t.Fatalf("third standby = %v, want the other transport", c)
	}
	inUse = append(inUse, c.Route())
	if _, _, ok := p.Next(inUse, Direct); !ok {
		t.Fatal("every route in use: a repeat is still better than nothing")
	}
}

func TestPlannerRoundRobinWithoutPathsUp(t *testing.T) {
	cands := []Candidate{
		cand("tcp", "", "192.0.2.1:1"), cand("tcp", "", "192.0.2.1:2"), cand("tcp", "", "192.0.2.1:3"),
	}
	p := NewPlanner(cands, nil)
	seen := map[string]bool{}
	for range cands {
		c, _, ok := p.Next(nil, Direct)
		if !ok {
			t.Fatal("no candidate")
		}
		seen[c.Key()] = true
	}
	if len(seen) != len(cands) {
		t.Fatalf("round robin visited %d of %d", len(seen), len(cands))
	}
}

func TestPlannerQuarantine(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	a, b := cand("tcp", "", "192.0.2.1:1"), cand("tcp", "", "192.0.2.2:1")
	p := NewPlanner([]Candidate{a, b}, clock)
	if d := p.Failed(a); d != time.Second {
		t.Fatalf("first backoff %v", d)
	}
	if d := p.Failed(a); d != 2*time.Second {
		t.Fatalf("second backoff %v", d)
	}
	for range 3 {
		c, _, ok := p.Next(nil, Direct)
		if !ok || c.Key() != b.Key() {
			t.Fatalf("got %v, want only the free candidate", c)
		}
	}
	p.Failed(b)
	_, wait, ok := p.Next(nil, Direct)
	if ok || wait != time.Second {
		t.Fatalf("all held: ok=%v wait=%v, want wait 1s for b", ok, wait)
	}
	if len(p.Quarantined()) != 2 {
		t.Fatalf("quarantined = %v", p.Quarantined())
	}
	now = now.Add(time.Second)
	if c, _, ok := p.Next(nil, Direct); !ok || c.Key() != b.Key() {
		t.Fatalf("after backoff got %v ok=%v", c, ok)
	}
	p.Succeeded(a)
	now = now.Add(-time.Second) // a was held 2 s; success clears it anyway
	if len(p.Quarantined()) != 1 {
		t.Fatalf("success did not clear: %v", p.Quarantined())
	}
}

func TestQuarantineCap(t *testing.T) {
	q := newQuarantine(time.Now)
	var d time.Duration
	for range 40 {
		d = q.fail("k")
	}
	if d != maxBackoff {
		t.Fatalf("backoff %v, want cap %v", d, maxBackoff)
	}
}

func TestPlannerRelay(t *testing.T) {
	direct := cand("tcp", "", "192.0.2.1:443")
	p := NewPlanner([]Candidate{direct}, nil)
	p.SetRelays([]core.NodeID{"r1", "r2"})
	p.Failed(direct)
	if _, _, ok := p.Next(nil, Direct); ok {
		t.Fatal("relay offered without relay allowed")
	}
	c, _, ok := p.Next(nil, Any)
	if !ok || !c.Relayed() {
		t.Fatalf("got %v, want a relay", c)
	}
	inUse := []Route{c.Route()}
	c2, _, ok := p.Next(inUse, Any)
	if !ok || !c2.Relayed() || c2.Via == c.Via {
		t.Fatalf("second relay %v, want the other relay", c2)
	}
	if distance(direct.Route(), c.Route()) != diffAll {
		t.Fatal("relayed and direct routes must be fully diverse")
	}
}
