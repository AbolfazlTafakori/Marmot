package controller

import (
	"cmp"
	"slices"
)

// rank orders a session's paths by score, keeping the current first path
// until a challenger is clearly better for several ticks (hysteresis).
func (c *Controller) rank(mem *sessionMem, session string, paths []PathSample, scores map[pathKey]float64) map[uint64]int {
	order := make([]uint64, 0, len(paths))
	for i := range paths {
		order = append(order, paths[i].PathID)
	}
	sc := func(id uint64) float64 { return scores[pathKey{session, id}] }
	slices.SortFunc(order, func(a, b uint64) int {
		if c := cmp.Compare(sc(a), sc(b)); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	best := order[0]
	_, firstLive := scores[pathKey{session, mem.first}]
	switch {
	case !firstLive || mem.first == 0:
		mem.first, mem.challenger, mem.streak = best, 0, 0
	case best == mem.first:
		mem.challenger, mem.streak = 0, 0
	case sc(best) <= switchRatio*sc(mem.first):
		if mem.challenger != best {
			mem.challenger, mem.streak = best, 0
		}
		mem.streak++
		if mem.streak >= switchTicks {
			mem.first, mem.challenger, mem.streak = best, 0, 0
		}
	default:
		mem.challenger, mem.streak = 0, 0
	}
	ranks := map[uint64]int{mem.first: 0}
	r := 1
	for _, id := range order {
		if id != mem.first {
			ranks[id] = r
			r++
		}
	}
	return ranks
}
