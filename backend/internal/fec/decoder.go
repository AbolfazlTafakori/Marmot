package fec

import (
	"time"
)

// Decoder limits.
const (
	maxGroups  = 512
	defaultTTL = time.Second
)

// Decoder collects received symbols per group and rebuilds missing source
// symbols once any k of a group's k+m have arrived. It is not safe for
// concurrent use.
type Decoder struct {
	TTL time.Duration    // how long a group is kept; 0 = 1 s
	Now func() time.Time // nil = time.Now

	groups     map[uint32]*group
	lastExpire time.Time
}

type group struct {
	created time.Time
	k, m    int // 0 until a parity symbol says
	size    int // padded symbol length, from a parity symbol
	shards  [MaxData + MaxParity][]byte
	count   int
	done    bool
}

// Recovered is a source symbol the decoder rebuilt.
type Recovered struct {
	Index  uint8
	Symbol []byte // padded to the group's symbol length
}

func (d *Decoder) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Decoder) group(id uint32) *group {
	if d.groups == nil {
		d.groups = map[uint32]*group{}
	}
	now := d.now()
	d.expire(now)
	g := d.groups[id]
	if g == nil {
		if len(d.groups) >= maxGroups {
			return nil
		}
		g = &group{created: now}
		d.groups[id] = g
	}
	return g
}

func (d *Decoder) expire(now time.Time) {
	if now.Sub(d.lastExpire) < 100*time.Millisecond {
		return
	}
	d.lastExpire = now
	ttl := d.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	for id, g := range d.groups {
		if now.Sub(g.created) > ttl {
			delete(d.groups, id)
		}
	}
}

// AddSource records source symbol index of group id, unpadded.
func (d *Decoder) AddSource(id uint32, index uint8, sym []byte) []Recovered {
	if int(index) >= MaxData {
		return nil
	}
	g := d.group(id)
	if g == nil || g.done || g.shards[index] != nil || (g.k > 0 && int(index) >= g.k) {
		return nil
	}
	if g.size > 0 && len(sym) > g.size {
		g.done = true // inconsistent group; give it up
		return nil
	}
	g.shards[index] = append([]byte(nil), sym...)
	g.count++
	return g.try()
}

// AddParity records parity symbol index (k..k+m-1) of group id.
func (d *Decoder) AddParity(id uint32, k, m, index uint8, parity []byte) []Recovered {
	if k == 0 || m == 0 || int(k) > MaxData || int(m) > MaxParity || index < k || int(index) >= int(k)+int(m) || len(parity) == 0 {
		return nil
	}
	g := d.group(id)
	if g == nil || g.done || g.shards[index] != nil {
		return nil
	}
	switch {
	case g.k == 0:
		g.k, g.m, g.size = int(k), int(m), len(parity)
		for i := g.k; i < MaxData; i++ {
			if g.shards[i] != nil { // a source index beyond k: not this group
				g.done = true
				return nil
			}
		}
		for i := range g.k {
			if g.shards[i] != nil && len(g.shards[i]) > g.size {
				g.done = true
				return nil
			}
		}
	case g.k != int(k) || g.m != int(m) || g.size != len(parity):
		g.done = true
		return nil
	}
	g.shards[index] = append([]byte(nil), parity...)
	g.count++
	return g.try()
}

// try rebuilds the missing sources once k symbols are in.
func (g *group) try() []Recovered {
	if g.k == 0 {
		return nil // no parity yet: nothing to rebuild with
	}
	missing := 0
	for i := range g.k {
		if g.shards[i] == nil {
			missing++
		}
	}
	if missing == 0 {
		g.done = true
		return nil
	}
	if g.count < g.k {
		return nil
	}
	g.done = true
	c, err := codec(g.k, g.m)
	if err != nil {
		return nil
	}
	shards := make([][]byte, g.k+g.m)
	for i := range shards {
		if s := g.shards[i]; s != nil {
			p := make([]byte, g.size)
			copy(p, s)
			shards[i] = p
		}
	}
	if err := c.ReconstructData(shards); err != nil {
		return nil
	}
	out := make([]Recovered, 0, missing)
	for i := range g.k {
		if g.shards[i] == nil {
			out = append(out, Recovered{Index: uint8(i), Symbol: shards[i]})
		}
	}
	return out
}
