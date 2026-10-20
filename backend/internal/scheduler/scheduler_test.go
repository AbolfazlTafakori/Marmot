package scheduler

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"marmot/internal/core"
)

func peers(o []int, c []Candidate) []core.NodeID {
	out := make([]core.NodeID, len(o))
	for i, k := range o {
		out[i] = c[k].Peer
	}
	return out
}

func TestDirectBeforeRelayed(t *testing.T) {
	c := []Candidate{
		{Peer: "r", Weight: 100, Relayed: true, RTT: time.Millisecond},
		{Peer: "a", Weight: 1, RTT: 90 * time.Millisecond},
		{Peer: "b", Weight: 1, RTT: 80 * time.Millisecond},
	}
	p := New()
	for _, class := range []core.Class{core.ClassTunneled, core.ClassVIP} {
		for range 50 {
			o := p.Order(class, c)
			if len(o) != 3 || c[o[2]].Peer != "r" {
				t.Fatalf("%v: order %v, relayed must be last", class, peers(o, c))
			}
		}
	}
}

func TestVIPByLatency(t *testing.T) {
	c := []Candidate{
		{Peer: "unknown", Weight: 9},
		{Peer: "slow", Weight: 9, RTT: 80 * time.Millisecond},
		{Peer: "fast-busy", Weight: 1, RTT: 20 * time.Millisecond, Streams: 5},
		{Peer: "fast-idle", Weight: 1, RTT: 20 * time.Millisecond},
	}
	got := peers(New().Order(core.ClassVIP, c), c)
	want := []core.NodeID{"fast-idle", "fast-busy", "slow", "unknown"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTunneledFollowsWeights(t *testing.T) {
	c := []Candidate{{Peer: "a", Weight: 1}, {Peer: "b", Weight: 3}}
	r := rand.New(rand.NewPCG(1, 2))
	p := &Picker{IntN: r.IntN}
	first := map[core.NodeID]int{}
	const n = 8000
	for range n {
		o := p.Order(core.ClassTunneled, c)
		if len(o) != 2 || o[0] == o[1] {
			t.Fatalf("order %v must hold every candidate once", o)
		}
		first[c[o[0]].Peer]++
	}
	share := float64(first["b"]) / n
	if share < 0.72 || share > 0.78 {
		t.Fatalf("b first in %.2f of picks, want about 0.75", share)
	}
}

func TestEmpty(t *testing.T) {
	if o := New().Order(core.ClassTunneled, nil); len(o) != 0 {
		t.Fatalf("got %v", o)
	}
}
