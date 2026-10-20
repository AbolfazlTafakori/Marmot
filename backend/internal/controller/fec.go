package controller

import "math"

// fec picks the parity count for a session's datagram paths: raised at
// once when loss crosses a threshold, lowered only after fecHold below.
func (c *Controller) fec(mem *sessionMem, in Input, paths []PathSample) int {
	switch in.FEC.Mode {
	case "off":
		return 0
	case "fixed":
		return in.FEC.MaxParity
	}
	loss, any := 0.0, false
	for i := range paths {
		p := &paths[i]
		if p.Datagram {
			any = true
			loss = math.Max(loss, c.paths[pathKey{p.Session, p.PathID}].loss)
		}
	}
	target := 0
	if any {
		for _, t := range fecThresholds {
			if loss > t {
				target++
			}
		}
	}
	target = min(target, in.FEC.MaxParity)
	switch {
	case target >= mem.fec:
		mem.fec, mem.fecSince = target, in.Now
	case in.Now.Sub(mem.fecSince) >= fecHold:
		mem.fec, mem.fecSince = target, in.Now
	}
	return mem.fec
}
