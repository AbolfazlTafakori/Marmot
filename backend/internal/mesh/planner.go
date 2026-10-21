package mesh

import (
	"context"
	"net/netip"
	"time"

	"marmot/internal/core"
	"marmot/internal/transport"
)

// TransportRelay names a relayed candidate: the path runs inside a stream
// through Via, which forwards it to the peer (ADR-0012).
const TransportRelay = "relay"

// Route says where a path that is already up runs, as far as diversity is
// concerned. Local may be invalid when it is not known.
type Route struct {
	Transport string
	Local     netip.Addr
	Remote    netip.AddrPort
	Via       core.NodeID // relay node; empty for a direct path
}

// Route returns the candidate's route.
func (c Candidate) Route() Route {
	return Route{Transport: c.Transport, Local: c.Local, Remote: c.Remote, Via: c.Via}
}

// Relayed reports whether the candidate runs through a relay node.
func (c Candidate) Relayed() bool { return c.Via != "" }

// Diversity weights (ADR-0011 §3): a difference in an earlier field
// outweighs differences in all later ones together.
const (
	diffPort      = 1
	diffTransport = 2
	diffLocal     = 4
	diffPeerAddr  = 8
	diffFamily    = 16
	diffAll       = diffFamily | diffPeerAddr | diffLocal | diffTransport | diffPort
)

// distance scores how differently two routes fail. A relayed route shares
// nothing with a direct one except the peer.
func distance(a, b Route) int {
	if a.Via != b.Via {
		if a.Via == "" || b.Via == "" {
			return diffAll
		}
		return diffPeerAddr
	}
	if a.Via != "" {
		return 0 // the same relay
	}
	d := 0
	if a.Remote.Addr().Is4() != b.Remote.Addr().Is4() {
		d |= diffFamily
	}
	if a.Remote.Addr() != b.Remote.Addr() {
		d |= diffPeerAddr
	}
	if a.Local.IsValid() && b.Local.IsValid() && a.Local != b.Local {
		d |= diffLocal
	}
	if a.Transport != b.Transport {
		d |= diffTransport
	}
	if a.Remote.Port() != b.Remote.Port() {
		d |= diffPort
	}
	return d
}

// Planner orders a peer's candidates: most diverse from the paths in use
// first, quarantined ones never. It is not safe for concurrent use; each
// peer link owns one.
type Planner struct {
	direct []Candidate
	relays []Candidate
	q      *quarantine
	next   int                 // rotates ties so equal candidates take turns
	pref   func(Candidate) int // lower first among equally diverse; nil = none
}

// SetPreference sets how the controller ranks candidates that are equally
// diverse: lower values are tried first (ADR-0015). Diversity still comes
// first, so a demoted transport is tried after the others, never dropped.
func (p *Planner) SetPreference(pref func(Candidate) int) { p.pref = pref }

// NewPlanner returns a planner over cands; now is the clock (nil = time.Now).
func NewPlanner(cands []Candidate, now func() time.Time) *Planner {
	if now == nil {
		now = time.Now
	}
	return &Planner{direct: cands, q: newQuarantine(now)}
}

// HasDirect reports whether the peer has any direct candidate.
func (p *Planner) HasDirect() bool { return len(p.direct) > 0 }

// SetDirect replaces the direct candidates, as rotation epochs and port
// hopping change them (ADR-0018). Quarantine is kept by route.
func (p *Planner) SetDirect(cands []Candidate) {
	p.direct = cands
	p.next = 0
}

// SetRelays replaces the relayed candidates; they change as relay nodes
// come and go. Quarantine of a relay that returns is kept.
func (p *Planner) SetRelays(vias []core.NodeID) {
	p.relays = p.relays[:0]
	for _, v := range vias {
		p.relays = append(p.relays, Candidate{Transport: TransportRelay, Via: v})
	}
}

// Kinds selects which candidates Next considers.
type Kinds uint8

// Candidate kinds.
const (
	Direct Kinds = 1 << iota
	Relayed
	Any = Direct | Relayed
)

// Next returns the candidate of the given kinds to try: not quarantined
// and as far as possible from every route in use, a route already in use
// last. When nothing can be tried, it returns false and how long until a
// candidate leaves quarantine (zero if there is none to wait for).
func (p *Planner) Next(inUse []Route, kinds Kinds) (Candidate, time.Duration, bool) {
	return p.choose(inUse, kinds, 0)
}

// NextDiverse is Next limited to candidates that differ from every route
// in use: it returns false rather than repeat a route.
func (p *Planner) NextDiverse(inUse []Route, kinds Kinds) (Candidate, bool) {
	c, _, ok := p.choose(inUse, kinds, 1)
	return c, ok
}

// SameRoute reports whether two routes fail together in every respect
// diversity looks at.
func SameRoute(a, b Route) bool { return distance(a, b) == 0 }

func (p *Planner) choose(inUse []Route, kinds Kinds, minScore int) (Candidate, time.Duration, bool) {
	var pool []Candidate
	if kinds&Direct != 0 {
		pool = append(pool, p.direct...)
	}
	if kinds&Relayed != 0 {
		pool = append(pool, p.relays...)
	}
	best, bestScore, bestPref := -1, -1, 0
	n := len(pool)
	for k := range n {
		i := (p.next + k) % n
		c := pool[i]
		if p.q.held(c.Key()) {
			continue
		}
		score := diffAll + 1 // nothing in use: every candidate is as good
		for _, r := range inUse {
			score = min(score, distance(c.Route(), r))
		}
		pref := 0
		if p.pref != nil {
			pref = p.pref(c)
		}
		// A route already up scores 0 and is taken only when nothing else
		// is free: a second connection on it still survives a reset of the
		// first.
		if score < minScore {
			continue
		}
		if score > bestScore || (score == bestScore && pref < bestPref) {
			best, bestScore, bestPref = i, score, pref
		}
	}
	if best >= 0 {
		p.next = best + 1
		return pool[best], 0, true
	}
	if n == 0 {
		return Candidate{}, 0, false
	}
	keys := make([]string, 0, n)
	for _, c := range pool {
		keys = append(keys, c.Key())
	}
	if t := p.q.earliest(keys); !t.IsZero() {
		return Candidate{}, max(t.Sub(p.q.now()), 0), false
	}
	return Candidate{}, 0, false
}

// Failed puts the candidate's route in quarantine and returns for how long.
func (p *Planner) Failed(c Candidate) time.Duration { return p.q.fail(c.Key()) }

// Succeeded clears the candidate's route from quarantine.
func (p *Planner) Succeeded(c Candidate) { p.q.ok(c.Key()) }

// Quarantined lists the routes currently held, for status.
func (p *Planner) Quarantined() []Held {
	var out []Held
	for _, c := range append(append([]Candidate(nil), p.direct...), p.relays...) {
		if n, until := p.q.failures(c.Key()); n > 0 && p.q.held(c.Key()) {
			out = append(out, Held{Key: c.Key(), Failures: n, Until: until})
		}
	}
	return out
}

// Held is one quarantined route.
type Held struct {
	Key      string
	Failures int
	Until    time.Time
}

// Dial connects a direct candidate with its transport.
func Dial(ctx context.Context, c Candidate) (transport.Conn, error) {
	tr, err := transport.Get(c.Transport)
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, transport.Endpoint{Addr: c.Remote, Options: c.Options}, c.Local)
}
