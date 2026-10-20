// Package scheduler decides which peer session carries a new stream
// (ARCHITECTURE §9.2). It is pure: it orders candidates and never touches
// a socket, so the policy is tested without a network.
//
// With session v1 a stream runs on one session, so the scheduler chooses
// among peers; the session keeps the stream alive across path failures.
// VIP duplication over two paths needs the multipath session v2 and
// arrives with it in Phase 3.
package scheduler

import (
	"cmp"
	"math/rand/v2"
	"slices"
	"time"

	"marmot/internal/core"
)

// Candidate is one peer that could carry a stream, with what the node
// knows of its session.
type Candidate struct {
	Peer    core.NodeID
	Weight  int           // configured peer weight, >= 1
	RTT     time.Duration // of the session's active path; 0 = unknown
	Relayed bool          // the session runs only through a relay node
	Streams int           // streams open on the session now
}

// Picker orders candidates. Its random source may be replaced in tests.
type Picker struct {
	IntN func(n int) int
}

// New returns a picker with a non-deterministic random source.
func New() *Picker {
	return &Picker{IntN: rand.IntN} // load spreading, not a secret
}

// Order returns the indexes of cands in the order they should be tried.
// Direct sessions always come before relayed ones, which cost another
// node's bandwidth and add a hop. Within each tier:
//   - tunneled: weighted random by peer weight, without replacement, so
//     load spreads as configured and every peer is a fallback;
//   - vip: lowest RTT first (unknown RTT last), then fewer streams, then
//     higher weight; small, latency-sensitive traffic takes the best path.
func (p *Picker) Order(class core.Class, cands []Candidate) []int {
	var direct, relayed []int
	for i := range cands {
		if cands[i].Relayed {
			relayed = append(relayed, i)
		} else {
			direct = append(direct, i)
		}
	}
	out := make([]int, 0, len(cands))
	for _, tier := range [][]int{direct, relayed} {
		if class == core.ClassVIP {
			out = append(out, byLatency(cands, tier)...)
		} else {
			out = append(out, p.weighted(cands, tier)...)
		}
	}
	return out
}

func byLatency(cands []Candidate, idx []int) []int {
	slices.SortStableFunc(idx, func(a, b int) int {
		ca, cb := &cands[a], &cands[b]
		if (ca.RTT == 0) != (cb.RTT == 0) {
			if ca.RTT == 0 {
				return 1
			}
			return -1
		}
		if c := cmp.Compare(ca.RTT, cb.RTT); c != 0 {
			return c
		}
		if c := cmp.Compare(ca.Streams, cb.Streams); c != 0 {
			return c
		}
		return cmp.Compare(cb.Weight, ca.Weight)
	})
	return idx
}

func (p *Picker) weighted(cands []Candidate, idx []int) []int {
	out := make([]int, 0, len(idx))
	rest := slices.Clone(idx)
	for len(rest) > 0 {
		total := 0
		for _, i := range rest {
			total += max(cands[i].Weight, 1)
		}
		r := p.IntN(total)
		k := len(rest) - 1
		for j, i := range rest {
			w := max(cands[i].Weight, 1)
			if r < w {
				k = j
				break
			}
			r -= w
		}
		out = append(out, rest[k])
		rest = slices.Delete(rest, k, k+1)
	}
	return out
}
