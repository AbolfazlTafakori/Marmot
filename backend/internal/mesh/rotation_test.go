package mesh

import (
	"net/netip"
	"testing"
	"time"
)

func TestRotatingAddrs(t *testing.T) {
	sub := netip.MustParsePrefix("2001:db8:1:2::/64")
	a := RotatingAddrs(sub, "iran-01", 7, 4)
	if len(a) != 4 {
		t.Fatalf("%d addresses", len(a))
	}
	seen := map[netip.Addr]bool{}
	for _, x := range a {
		if !sub.Contains(x) || seen[x] {
			t.Fatalf("address %v outside the subnet or repeated", x)
		}
		seen[x] = true
	}
	if b := RotatingAddrs(sub, "iran-01", 7, 4); b[0] != a[0] || b[3] != a[3] {
		t.Fatal("not deterministic")
	}
	if c := RotatingAddrs(sub, "iran-01", 8, 4); c[0] == a[0] {
		t.Fatal("same address in the next epoch")
	}
	if d := RotatingAddrs(sub, "iran-02", 7, 4); d[0] == a[0] {
		t.Fatal("same address for another node")
	}
	if RotatingAddrs(netip.MustParsePrefix("2001:db8::/48"), "x", 1, 2) != nil ||
		RotatingAddrs(netip.MustParsePrefix("192.0.2.0/24"), "x", 1, 2) != nil {
		t.Fatal("non-/64 subnet produced addresses")
	}
}

func TestEpoch(t *testing.T) {
	at := time.Unix(1000, 0)
	if Epoch(at, 5*time.Minute) != 3 || Epoch(at.Add(5*time.Minute), 5*time.Minute) != 4 || Epoch(at, 0) != 0 {
		t.Fatal("epoch numbering")
	}
}

func TestSetDirectKeepsQuarantine(t *testing.T) {
	a := cand("tls", "", "192.0.2.1:443")
	b := cand("tls", "", "192.0.2.2:443")
	p := NewPlanner([]Candidate{a}, nil)
	p.Failed(a)
	p.SetDirect([]Candidate{a, b})
	for range 3 {
		if c, _, ok := p.Next(nil, Direct); !ok || c.Key() != b.Key() {
			t.Fatalf("got %v: the quarantined route must stay held", c)
		}
	}
}

func TestNextDiverse(t *testing.T) {
	a := cand("quic", "", "192.0.2.1:443")
	b := cand("tls", "", "192.0.2.1:443")
	p := NewPlanner([]Candidate{a, b}, nil)
	if c, ok := p.NextDiverse([]Route{a.Route()}, Direct); !ok || c.Key() != b.Key() {
		t.Fatalf("got %v %v, want the tls route", c, ok)
	}
	if _, ok := p.NextDiverse([]Route{a.Route(), b.Route()}, Direct); ok {
		t.Fatal("repeated a route although every route is in use")
	}
	if !SameRoute(a.Route(), a.Route()) || SameRoute(a.Route(), b.Route()) {
		t.Fatal("SameRoute")
	}
}
