package session

import (
	"math/rand/v2"
	"testing"
)

// TestRangeSetMatchesModel checks random adds and removes against a plain
// bitmap.
func TestRangeSetMatchesModel(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	const size = 300
	for round := range 200 {
		var r rangeSet
		var model [size]bool
		for range 40 {
			lo := uint64(rng.IntN(size))
			hi := lo + uint64(rng.IntN(20))
			hi = min(hi, size)
			if rng.IntN(3) == 0 {
				r.remove(lo, hi)
				for v := lo; v < hi; v++ {
					model[v] = false
				}
			} else {
				r.add(lo, hi)
				for v := lo; v < hi; v++ {
					model[v] = true
				}
			}
			for v := range uint64(size) {
				if r.contains(v) != model[v] {
					t.Fatalf("round %d: contains(%d) = %v, model %v; spans %v", round, v, r.contains(v), model[v], r.spans())
				}
			}
			for i, s := range r.spans() {
				if s.lo >= s.hi || (i > 0 && r.spans()[i-1].hi >= s.lo) {
					t.Fatalf("round %d: spans not disjoint and separated: %v", round, r.spans())
				}
			}
		}
	}
}

func TestRangeSetTrimAndLimit(t *testing.T) {
	var r rangeSet
	r.add(0, 10)
	r.add(20, 30)
	r.add(40, 50)
	r.trimBelow(25)
	if f, _ := r.first(); f != (span{25, 30}) {
		t.Fatalf("after trim: %v", r.spans())
	}
	r.add(60, 70)
	if floor := r.limit(2); floor != 40 || len(r.spans()) != 2 {
		t.Fatalf("limit: floor %d spans %v", floor, r.spans())
	}
	if floor := r.limit(5); floor != 0 {
		t.Fatalf("limit with room: floor %d", floor)
	}
	if l, _ := r.last(); l != (span{60, 70}) {
		t.Fatalf("last %v", l)
	}
}
