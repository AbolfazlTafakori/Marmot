package node

import (
	"context"
	"net/netip"
	"time"

	"marmot/internal/config"
	"marmot/internal/mesh"
	"marmot/internal/session"
)

// linkRoutes is where a link's candidates come from. With IPv6 rotation
// or port hopping they change over time and are rebuilt on every pass of
// the link (ADR-0018).
type linkRoutes struct {
	build   func(now time.Time) []mesh.Candidate
	stale   func(now time.Time, local, remote netip.Addr) bool
	dynamic bool
}

// routesFor describes the candidates of peer p under config c, and lists
// transports this build does not have.
func routesFor(c *config.Config, p config.Peer) (linkRoutes, []string) {
	rot := c.Local.IPv6Rotation
	epochLen := rot.Epoch.D()
	localNet, _ := netip.ParsePrefix(c.Local.IPv6Subnet)
	peerNet, _ := netip.ParsePrefix(p.IPv6Subnet)
	locals := func(now time.Time) mesh.Locals {
		l := baseLocals(c)
		if rot.Enabled {
			l.V6 = mesh.RotatingAddrs(localNet, c.Node.ID, mesh.Epoch(now, epochLen), rot.Active)
		}
		return l
	}
	remotes := func(now time.Time) []netip.Addr {
		if !peerNet.IsValid() {
			return nil
		}
		return mesh.RotatingAddrs(peerNet, p.ID, mesh.Epoch(now, epochLen), rot.Active)
	}
	_, skipped := mesh.Expand(peerSpec(&p), baseLocals(c), transportKnown)
	r := linkRoutes{
		build: func(now time.Time) []mesh.Candidate {
			spec := peerSpec(&p)
			spec.Addrs = append(spec.Addrs, remotes(now)...)
			cands, _ := mesh.Expand(spec, locals(now), transportKnown)
			return cands
		},
		stale: func(now time.Time, local, remote netip.Addr) bool {
			if rot.Enabled && localNet.Contains(local) && !contains(locals(now).V6, local) {
				return true
			}
			return peerNet.IsValid() && peerNet.Contains(remote) && !contains(remotes(now), remote)
		},
		dynamic: rot.Enabled || peerNet.IsValid(),
	}
	for i := range p.Endpoints {
		if p.Endpoints[i].Dialed() && p.Endpoints[i].HopInterval != 0 {
			r.dynamic = true
		}
	}
	return r, skipped
}

func contains(as []netip.Addr, a netip.Addr) bool {
	for _, x := range as {
		if x == a {
			return true
		}
	}
	return false
}

// refreshRoutes rebuilds the planner's candidates: a new epoch brings new
// addresses, and a port range is sampled again.
func (l *peerLink) refreshRoutes(now time.Time) {
	if !l.routes.dynamic {
		return
	}
	cands := l.routes.build(now)
	l.planMu.Lock()
	l.plan.SetDirect(cands)
	l.planMu.Unlock()
}

// refreshPaths replaces, make-before-break, one path of a v2 session that
// runs on an address of an earlier epoch or has outlived its endpoint's
// hop interval (ADR-0018).
func (l *peerLink) refreshPaths(ctx context.Context, s session.PeerSession, now time.Time) {
	r, ok := s.(retirer)
	if !ok || !l.routes.dynamic {
		return
	}
	st := s.Stats()
	for i := range st.Paths {
		p := &st.Paths[i]
		if p.Draining || isRelayed(p.Meta) {
			continue
		}
		local, _ := netip.ParseAddrPort(p.Meta.Local)
		remote, _ := netip.ParseAddrPort(p.Meta.Remote)
		reason := ""
		switch hop := l.hopOf(p.Meta); {
		case l.routes.stale(now, local.Addr().Unmap(), remote.Addr().Unmap()):
			reason = "rotation"
		case hop > 0 && now.Sub(p.Registered) >= hop:
			reason = "port hop"
		default:
			continue
		}
		if l.replacePath(ctx, s, r, p.ID, reason) {
			return // one per pass
		}
	}
}

// noteHop remembers the hop interval of a path's candidate.
func (l *peerLink) noteHop(meta session.PathMeta, hop time.Duration) {
	if hop <= 0 {
		return
	}
	l.mu.Lock()
	if l.hops == nil {
		l.hops = map[string]time.Duration{}
	}
	l.hops[meta.Transport+"|"+meta.Remote] = hop
	l.mu.Unlock()
}

func (l *peerLink) hopOf(meta session.PathMeta) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hops[meta.Transport+"|"+meta.Remote]
}
