package session

import "slices"

// span is the half-open interval [lo, hi).
type span struct{ lo, hi uint64 }

// rangeSet is a set of uint64 kept as sorted, disjoint, non-adjacent
// spans. Session v2 uses it for received packet numbers, acknowledged and
// lost stream bytes, and received stream data. It is not safe for
// concurrent use.
type rangeSet struct {
	s []span
}

// add inserts [lo, hi).
func (r *rangeSet) add(lo, hi uint64) {
	if lo >= hi {
		return
	}
	// First span that ends at or after lo (could merge with it).
	i, _ := slices.BinarySearchFunc(r.s, lo, func(s span, v uint64) int {
		if s.hi < v {
			return -1
		}
		return 1
	})
	j := i
	for j < len(r.s) && r.s[j].lo <= hi {
		lo = min(lo, r.s[j].lo)
		hi = max(hi, r.s[j].hi)
		j++
	}
	r.s = slices.Replace(r.s, i, j, span{lo, hi})
}

// remove deletes [lo, hi).
func (r *rangeSet) remove(lo, hi uint64) {
	if lo >= hi {
		return
	}
	i, _ := slices.BinarySearchFunc(r.s, lo, func(s span, v uint64) int {
		if s.hi <= v {
			return -1
		}
		return 1
	})
	j := i
	for j < len(r.s) && r.s[j].lo < hi {
		j++
	}
	if i == j {
		return
	}
	var keep [2]span
	n := 0
	if r.s[i].lo < lo {
		keep[n] = span{r.s[i].lo, lo}
		n++
	}
	if r.s[j-1].hi > hi {
		keep[n] = span{hi, r.s[j-1].hi}
		n++
	}
	r.s = slices.Replace(r.s, i, j, keep[:n]...)
}

// contains reports whether v is in the set.
func (r *rangeSet) contains(v uint64) bool {
	_, found := slices.BinarySearchFunc(r.s, v, func(s span, v uint64) int {
		switch {
		case s.hi <= v:
			return -1
		case s.lo > v:
			return 1
		}
		return 0
	})
	return found
}

// first returns the lowest span.
func (r *rangeSet) first() (span, bool) {
	if len(r.s) == 0 {
		return span{}, false
	}
	return r.s[0], true
}

// last returns the highest span.
func (r *rangeSet) last() (span, bool) {
	if len(r.s) == 0 {
		return span{}, false
	}
	return r.s[len(r.s)-1], true
}

func (r *rangeSet) empty() bool { return len(r.s) == 0 }

// spans returns the spans, lowest first. The slice must not be modified.
func (r *rangeSet) spans() []span { return r.s }

// trimBelow drops everything below v.
func (r *rangeSet) trimBelow(v uint64) {
	i := 0
	for i < len(r.s) && r.s[i].hi <= v {
		i++
	}
	r.s = r.s[i:]
	if len(r.s) > 0 && r.s[0].lo < v {
		r.s[0].lo = v
	}
}

// limit keeps at most n spans, dropping the lowest, and returns the
// lowest value still tracked (0 when nothing was dropped).
func (r *rangeSet) limit(n int) uint64 {
	if len(r.s) <= n {
		return 0
	}
	drop := len(r.s) - n
	floor := r.s[drop].lo
	r.s = slices.Delete(r.s, 0, drop)
	return floor
}
