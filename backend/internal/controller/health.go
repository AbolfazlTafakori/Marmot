package controller

import (
	"math"

	"marmot/internal/core"
)

// health rates each peer from its best path: loss lowers it, and a peer
// reachable only through relays counts half.
func (c *Controller) health(paths []PathSample) map[core.NodeID]float64 {
	type agg struct {
		bestLoss float64
		direct   bool
		any      bool
	}
	peers := map[core.NodeID]*agg{}
	for i := range paths {
		p := &paths[i]
		a := peers[p.Peer]
		if a == nil {
			a = &agg{bestLoss: 1}
			peers[p.Peer] = a
		}
		a.any = true
		a.bestLoss = math.Min(a.bestLoss, c.paths[pathKey{p.Session, p.PathID}].loss)
		if !p.Relayed {
			a.direct = true
		}
	}
	out := make(map[core.NodeID]float64, len(peers))
	for id, a := range peers {
		h := 1 - 2*a.bestLoss
		if !a.direct {
			h /= 2
		}
		out[id] = math.Max(math.Min(h, 1), minHealth)
	}
	return out
}
