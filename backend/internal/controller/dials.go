package controller

import (
	"net/netip"
	"slices"
)

// dialsTick records dial results and demotes a transport that failed on
// several peer addresses over some seconds without a single success
// (ADR-0015 §5). A burst within one moment (peers still starting) is not
// a block.
func (c *Controller) dialsTick(in Input) {
	for _, d := range in.Dials {
		c.dials[d.Transport] = append(c.dials[d.Transport], dialRecord{at: in.Now, remote: d.Remote, ok: d.OK})
		if d.OK {
			delete(c.demoted, d.Transport)
		}
	}
	for t, recs := range c.dials {
		recs = slices.DeleteFunc(recs, func(r dialRecord) bool { return in.Now.Sub(r.at) > dialWindow })
		if len(recs) == 0 {
			delete(c.dials, t)
			continue
		}
		c.dials[t] = recs
		failures, ok := 0, false
		addrs := map[netip.Addr]bool{}
		for _, r := range recs {
			if r.ok {
				ok = true
				break
			}
			failures++
			addrs[r.remote] = true
		}
		spread := recs[len(recs)-1].at.Sub(recs[0].at)
		if !ok && failures >= demoteFailures && len(addrs) >= demoteAddresses && spread >= demoteSpread {
			if _, already := c.demoted[t]; !already {
				c.demoted[t] = in.Now.Add(demoteFor)
			}
		}
	}
	for t, until := range c.demoted {
		if !in.Now.Before(until) {
			delete(c.demoted, t)
		}
	}
}
