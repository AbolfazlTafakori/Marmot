package node

import (
	"context"
	"time"

	"marmot/internal/mesh"
	"marmot/internal/session"
)

// Path maintenance of a peer link's session: standbys, relay fallback and
// return, lossy-path replacement and rotation (ADR-0011, ADR-0012,
// ADR-0015).

// maintain keeps standbys filled, moves the session off a relay once a
// direct route works again, and rotates paths, until the session ends or
// the link stops.
func (l *peerLink) maintain(ctx context.Context, s session.PeerSession) {
	t := time.NewTicker(maintainEvery)
	defer t.Stop()
	lastRotate, baseBytes := time.Now(), sessionBytes(s)
	for {
		l.refreshRoutes(time.Now())
		l.replaceLossy(ctx, s)
		l.refreshPaths(ctx, s, time.Now())
		l.diversify(ctx, s)
		l.fillStandby(ctx, s)
		// After the standbys: direct paths that just came back let the
		// session leave the relay in this same pass.
		if l.leaveRelay(ctx, s) {
			lastRotate, baseBytes = time.Now(), sessionBytes(s)
		}
		if time.Since(lastRotate) >= l.deps.rotateInterval || sessionBytes(s)-baseBytes >= l.deps.rotateBytes {
			l.rotate(ctx, s)
			lastRotate, baseBytes = time.Now(), sessionBytes(s)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.Done():
			return
		case <-l.wake:
		case <-t.C:
		}
	}
}

func sessionBytes(s session.PeerSession) uint64 {
	st := s.Stats()
	return st.SentOff + st.RecvOff
}

// fillStandby joins paths until the session has 1 + standby of them,
// each as different as possible from those already up.
func (l *peerLink) fillStandby(ctx context.Context, s session.PeerSession) {
	for ctx.Err() == nil {
		st := s.Stats()
		if len(st.Paths) >= 1+l.deps.standby {
			return
		}
		c, _, ok := l.next(routes(st))
		if !ok {
			return
		}
		if err := l.join(ctx, s, c, false); err != nil {
			l.fail(c, "standby join failed", err)
		}
	}
}

// leaveRelayV2 retires the relayed paths of a v2 session once a direct
// path is healthy again, trying a direct route first if there is none:
// v2 uses every path, so with a direct one up the relayed ones are idle
// (ADR-0013 §4) and only hold the relay node's resources. A failing direct
// route goes to quarantine, so it is not dialed on every pass.
func (l *peerLink) leaveRelayV2(ctx context.Context, s session.PeerSession, st session.ConnStats, r retirer) bool {
	relayed := false
	for i := range st.Paths {
		if isRelayed(st.Paths[i].Meta) && !st.Paths[i].Draining {
			relayed = true
		}
	}
	if !relayed {
		return false
	}
	if !healthyDirect(st) {
		c, ok := l.nextOf(routes(st), mesh.Direct, nil)
		if !ok {
			return false
		}
		if err := l.join(ctx, s, c, false); err != nil {
			l.fail(c, "direct route still failing", err)
			return false
		}
		if st = s.Stats(); !healthyDirect(st) {
			return false
		}
	}
	left := false
	for i := range st.Paths {
		if p := &st.Paths[i]; isRelayed(p.Meta) && !p.Draining && r.Retire(p.ID) {
			left = true
		}
	}
	if left {
		l.deps.log.Info("session back on a direct path")
		l.deps.events.publish(EventRotation, map[string]any{"peer": l.id, "reason": "direct"})
	}
	return left
}

// watchRelay runs relayFallback for a v2 session on its own goroutine,
// woken by kicks (a path turned suspect or went down), so that dials the
// maintain loop is waiting on never delay the fallback. It returns a
// function that stops the watcher and waits for it.
func (l *peerLink) watchRelay(ctx context.Context, s session.PeerSession) func() {
	if _, v2 := s.(retirer); !v2 {
		return func() {}
	}
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(maintainEvery)
		defer t.Stop()
		for {
			l.relayFallback(wctx, s)
			select {
			case <-wctx.Done():
				return
			case <-s.Done():
				return
			case <-l.relayWake:
			case <-t.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// relayFallback joins a relayed path to a v2 session as soon as no direct
// path is healthy, beside the suspect ones, instead of waiting for them to
// die and for direct dials to time out (ADR-0012, ADR-0013 §5).
func (l *peerLink) relayFallback(ctx context.Context, s session.PeerSession) {
	st := s.Stats()
	if healthyDirect(st) {
		return
	}
	for i := range st.Paths {
		if isRelayed(st.Paths[i].Meta) && !st.Paths[i].Draining {
			return // one is enough; the planner adds more as standbys
		}
	}
	c, ok := l.nextOf(routes(st), mesh.Relayed, l.deps.relayVias(l.id))
	if !ok {
		return
	}
	if err := l.join(ctx, s, c, false); err != nil {
		l.fail(c, "relay join failed", err)
		return
	}
	l.deps.log.Info("relay path added: no direct path is healthy", "via", c.Key())
}

// healthyDirect reports whether a direct path is up and acknowledged.
func healthyDirect(st session.ConnStats) bool {
	for i := range st.Paths {
		p := &st.Paths[i]
		if !isRelayed(p.Meta) && !p.Suspect && !p.Draining {
			return true
		}
	}
	return false
}

// retirer is implemented by session v2, which can drain a given path.
type retirer interface{ Retire(pathID uint64) bool }

// replaceLossy replaces each path the controller reported as lossy:
// a new path joins first, then the lossy one drains (ADR-0015).
func (l *peerLink) replaceLossy(ctx context.Context, s session.PeerSession) {
	r, ok := s.(retirer)
	ids := l.takeReplace()
	if !ok {
		return
	}
	for _, id := range ids {
		l.replacePath(ctx, s, r, id, "lossy")
	}
}

// diversify replaces, make-before-break, a v2 path that repeats the route
// of another one while a route that differs from all of them is free. A
// repeat is taken only when nothing else could be dialed (a peer still
// starting, say); once the other routes leave quarantine, the session
// should not stay less diverse than it can be (ADR-0011).
func (l *peerLink) diversify(ctx context.Context, s session.PeerSession) {
	r, ok := s.(retirer)
	if !ok {
		return
	}
	st := s.Stats()
	var live []*session.PathInfo
	for i := range st.Paths {
		if !st.Paths[i].Draining {
			live = append(live, &st.Paths[i])
		}
	}
	for j := 1; j < len(live); j++ {
		for i := range j {
			if !mesh.SameRoute(routeOf(live[i].Meta), routeOf(live[j].Meta)) {
				continue
			}
			var others []mesh.Route
			for k := range live {
				if k != j {
					others = append(others, routeOf(live[k].Meta))
				}
			}
			l.planMu.Lock()
			l.applyPreferenceLocked()
			c, ok := l.plan.NextDiverse(others, mesh.Direct)
			l.planMu.Unlock()
			if !ok {
				// Nothing more diverse is free; a repeat beyond the
				// paths the session should have is only extra load.
				if len(live) > 1+l.deps.standby && r.Retire(live[j].ID) {
					l.deps.log.Debug("surplus repeated route retired")
				}
				return
			}
			if err := l.join(ctx, s, c, false); err != nil {
				l.fail(c, "diverse join failed", err)
				return
			}
			if r.Retire(live[j].ID) {
				l.deps.log.Debug("repeated route replaced by a diverse one", "via", c.Key())
				l.deps.events.publish(EventRotation, map[string]any{"peer": l.id, "reason": "diversity"})
			}
			return // one per pass
		}
	}
}

// replacePath joins a new path, then drains path id: make-before-break.
// It reports whether the path was there to replace.
func (l *peerLink) replacePath(ctx context.Context, s session.PeerSession, r retirer, id uint64, reason string) bool {
	st := s.Stats()
	found := false
	var others []mesh.Route
	for i := range st.Paths {
		if st.Paths[i].ID == id {
			found = true
		} else {
			others = append(others, routeOf(st.Paths[i].Meta))
		}
	}
	if !found {
		return false
	}
	if c, _, ok := l.next(others); ok {
		if err := l.join(ctx, s, c, false); err != nil {
			l.fail(c, "replacement join failed", err)
		}
	}
	if !r.Retire(id) {
		return false
	}
	l.deps.log.Debug("path replaced", "reason", reason)
	l.deps.events.publish(EventRotation, map[string]any{"peer": l.id, "reason": reason})
	return true
}

// leaveRelay moves a session whose active path is relayed onto a direct
// route, make-before-break, if one is free. It reports whether it did.
func (l *peerLink) leaveRelay(ctx context.Context, s session.PeerSession) bool {
	st := s.Stats()
	if r, ok := s.(retirer); ok {
		return l.leaveRelayV2(ctx, s, st, r)
	}
	active, ok := activePath(st)
	if !ok || !isRelayed(active.Meta) {
		return false
	}
	c, ok := l.nextOf(routes(st), mesh.Direct, nil)
	if !ok {
		return false
	}
	if err := l.join(ctx, s, c, true); err != nil {
		l.fail(c, "direct route still failing", err)
		return false
	}
	l.deps.log.Info("session back on a direct path", "via", c.Key())
	l.deps.events.publish(EventRotation, map[string]any{"peer": l.id, "reason": "direct"})
	return true
}

// rotate replaces the active path with a fresh one (new keys, ideally a
// different route) before closing the old one.
func (l *peerLink) rotate(ctx context.Context, s session.PeerSession) {
	// The active path is being replaced, so only the standbys count as in
	// use; with a single route the rotation reuses it with fresh keys.
	st := s.Stats()
	var standbys []mesh.Route
	for i := range st.Paths {
		if !st.Paths[i].Active {
			standbys = append(standbys, routeOf(st.Paths[i].Meta))
		}
	}
	c, _, ok := l.next(standbys)
	if !ok {
		return
	}
	if err := l.join(ctx, s, c, true); err != nil {
		l.fail(c, "rotation failed", err)
		return
	}
	l.deps.log.Debug("path rotated", "via", c.Key())
	l.deps.events.publish(EventRotation, map[string]any{"peer": l.id})
}

func (l *peerLink) join(ctx context.Context, s session.PeerSession, c mesh.Candidate, rotate bool) error {
	conn, meta, err := l.dial(ctx, c)
	if err != nil {
		return err
	}
	jctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := s.Join(jctx, conn, meta, rotate); err != nil {
		return err
	}
	l.succeeded(c)
	l.noteHop(meta, c.Hop)
	return nil
}

// routes lists the routes of a session's live paths.
func routes(st session.ConnStats) []mesh.Route {
	out := make([]mesh.Route, 0, len(st.Paths))
	for i := range st.Paths {
		out = append(out, routeOf(st.Paths[i].Meta))
	}
	return out
}

func activePath(st session.ConnStats) (session.PathInfo, bool) {
	for i := range st.Paths {
		if st.Paths[i].Active {
			return st.Paths[i], true
		}
	}
	return session.PathInfo{}, false
}

func activeMeta(s session.PeerSession) string {
	if p, ok := activePath(s.Stats()); ok {
		return p.Meta.String()
	}
	return ""
}
