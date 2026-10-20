package node

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/mesh"
	"marmot/internal/session"
	"marmot/internal/transport"
)

const (
	dialTimeout    = 10 * time.Second
	maintainEvery  = 2 * time.Second
	minRedialDelay = 100 * time.Millisecond
	maxRedialDelay = 30 * time.Second
)

// linkDeps is what a peerLink needs from its node. It is a snapshot taken
// when the link starts; a reload that changes it restarts the link.
type linkDeps struct {
	local          *crypto.Identity
	localID        core.NodeID
	caps           uint32
	conn           session.ConnConfig
	standby        int
	rotateBytes    uint64
	rotateInterval time.Duration
	events         *eventBus
	serve          func(*session.MuxSession) // starts the stream accept loop
	relayVias      func(target core.NodeID) []core.NodeID
	dialRelay      func(ctx context.Context, via, target core.NodeID) (transport.Conn, error)
	log            *slog.Logger
}

// peerLink keeps one outbound session to a peer alive: it dials, keeps
// hot-standby paths joined, rotates paths make-before-break, and redials
// when the session ends. Which route to try comes from the peer's
// mesh.Planner: diverse routes first, failed ones in quarantine, relayed
// routes only while no direct path is up (ADR-0011, ADR-0012).
type peerLink struct {
	deps linkDeps
	cfg  config.Peer
	id   core.NodeID
	key  ed25519.PublicKey
	plan *mesh.Planner // owned by run

	relayTurn bool // whether a relayed route goes first next time; owned by run

	mu   sync.Mutex
	sess *session.MuxSession

	wake   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
}

func startLink(deps linkDeps, p config.Peer, key ed25519.PublicKey, cands []mesh.Candidate) *peerLink {
	ctx, cancel := context.WithCancel(context.Background())
	l := &peerLink{
		deps: deps, cfg: p, id: core.NodeID(p.ID), key: key, plan: mesh.NewPlanner(cands, nil),
		wake: make(chan struct{}, 1), cancel: cancel, done: make(chan struct{}),
	}
	l.deps.log = deps.log.With("peer", p.ID)
	go l.run(ctx)
	return l
}

// stop ends the link and its session and waits for it.
func (l *peerLink) stop() {
	l.cancel()
	<-l.done
}

// session returns the live outbound session, or nil.
func (l *peerLink) session() *session.MuxSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sess
}

func (l *peerLink) setSession(s *session.MuxSession) {
	l.mu.Lock()
	l.sess = s
	l.mu.Unlock()
}

// kick makes the link look at its paths now, e.g. because a relay came up.
func (l *peerLink) kick() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *peerLink) run(ctx context.Context) {
	defer close(l.done)
	if !l.plan.HasDirect() {
		return // inbound-only peer: it dials us
	}
	for ctx.Err() == nil {
		s, wait := l.establish(ctx)
		if s == nil {
			if !l.sleep(ctx, min(max(wait, minRedialDelay), maxRedialDelay)) {
				return
			}
			continue
		}
		l.setSession(s)
		l.deps.log.Info("session up", "via", activeMeta(s))
		l.deps.events.publish(EventPeerState, map[string]any{"peer": l.id, "state": "up"})
		l.deps.serve(s)
		l.maintain(ctx, s)
		l.setSession(nil)
		_ = s.Close()
		l.deps.log.Info("session down", "err", s.Err())
		l.deps.events.publish(EventPeerState, map[string]any{"peer": l.id, "state": "down"})
	}
}

// sleep waits for d, a kick or the end of the link.
func (l *peerLink) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-l.wake:
	case <-t.C:
	}
	return true
}

// next asks the planner for a route. While a direct path is up, only
// direct routes are tried. Otherwise direct and relayed routes take turns:
// a blackholed direct route costs a full dial timeout per try, and waiting
// for every direct route to fail first could keep a working relay unused
// for minutes. When there is nothing to try, wait is how long until a
// quarantined route frees up (zero = unknown).
func (l *peerLink) next(inUse []mesh.Route) (mesh.Candidate, time.Duration, bool) {
	if hasDirect(inUse) {
		return l.plan.Next(inUse, mesh.Direct)
	}
	l.plan.SetRelays(l.deps.relayVias(l.id))
	order := [2]mesh.Kinds{mesh.Direct, mesh.Relayed}
	if l.relayTurn {
		order[0], order[1] = order[1], order[0]
	}
	l.relayTurn = !l.relayTurn
	var wait time.Duration
	for _, k := range order {
		c, w, ok := l.plan.Next(inUse, k)
		if ok {
			return c, 0, true
		}
		if w > 0 && (wait == 0 || w < wait) {
			wait = w
		}
	}
	return mesh.Candidate{}, wait, false
}

func hasDirect(inUse []mesh.Route) bool {
	for _, r := range inUse {
		if r.Via == "" {
			return true
		}
	}
	return false
}

// establish tries routes until a session comes up or every route is in
// quarantine.
func (l *peerLink) establish(ctx context.Context) (*session.MuxSession, time.Duration) {
	for ctx.Err() == nil {
		c, wait, ok := l.next(nil)
		if !ok {
			return nil, wait
		}
		conn, meta, err := l.dial(ctx, c)
		if err != nil {
			l.fail(c, "dial failed", err)
			continue
		}
		cc := l.deps.conn
		cc.OnPathDown = l.onPathDown
		cc.Logger = l.deps.log
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		s, err := session.Dial(dctx, session.DialConfig{
			Local: l.deps.local, LocalID: l.deps.localID, Peer: l.id, PeerKey: l.key,
			Caps: l.deps.caps, Conn: cc,
		}, conn, meta)
		cancel()
		if err != nil {
			l.fail(c, "handshake failed", err)
			continue
		}
		l.plan.Succeeded(c)
		return s, 0
	}
	return nil, 0
}

func (l *peerLink) fail(c mesh.Candidate, what string, err error) {
	d := l.plan.Failed(c)
	l.deps.log.Debug(what, "via", c.Key(), "err", err, "quarantine", d)
}

func (l *peerLink) dial(ctx context.Context, c mesh.Candidate) (transport.Conn, session.PathMeta, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if c.Relayed() {
		conn, err := l.deps.dialRelay(dctx, c.Via, l.id)
		if err != nil {
			return nil, session.PathMeta{}, err
		}
		meta := session.PathMeta{Transport: mesh.TransportRelay,
			Local: conn.LocalAddr().String(), Remote: conn.RemoteAddr().String()}
		return conn, meta, nil
	}
	conn, err := mesh.Dial(dctx, c)
	if err != nil {
		return nil, session.PathMeta{}, err
	}
	meta := session.PathMeta{Transport: c.Transport, Local: conn.LocalAddr().String(), Remote: c.Remote.String()}
	return conn, meta, nil
}

func (l *peerLink) onPathDown(info session.PathInfo, cause error) {
	typ := EventPathState
	if info.Active {
		typ = EventFailover
	}
	l.deps.events.publish(typ, map[string]any{
		"peer": l.id, "path": info.ID, "transport": info.Meta.Transport,
		"remote": info.Meta.Remote, "state": "down", "reason": fmt.Sprint(cause),
	})
	l.kick()
}

// maintain keeps standbys filled, moves the session off a relay once a
// direct route works again, and rotates paths, until the session ends or
// the link stops.
func (l *peerLink) maintain(ctx context.Context, s *session.MuxSession) {
	t := time.NewTicker(maintainEvery)
	defer t.Stop()
	lastRotate, baseBytes := time.Now(), sessionBytes(s)
	for {
		if l.leaveRelay(ctx, s) {
			lastRotate, baseBytes = time.Now(), sessionBytes(s)
		}
		l.fillStandby(ctx, s)
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

func sessionBytes(s *session.MuxSession) uint64 {
	st := s.Stats()
	return st.SentOff + st.RecvOff
}

// fillStandby joins paths until the session has 1 + standby of them,
// each as different as possible from those already up.
func (l *peerLink) fillStandby(ctx context.Context, s *session.MuxSession) {
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

// leaveRelay moves a session whose active path is relayed onto a direct
// route, make-before-break, if one is free. It reports whether it did.
func (l *peerLink) leaveRelay(ctx context.Context, s *session.MuxSession) bool {
	st := s.Stats()
	active, ok := activePath(st)
	if !ok || !isRelayed(active.Meta) {
		return false
	}
	c, _, ok := l.plan.Next(routes(st), mesh.Direct)
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
func (l *peerLink) rotate(ctx context.Context, s *session.MuxSession) {
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

func (l *peerLink) join(ctx context.Context, s *session.MuxSession, c mesh.Candidate, rotate bool) error {
	conn, meta, err := l.dial(ctx, c)
	if err != nil {
		return err
	}
	jctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := s.Join(jctx, conn, meta, rotate); err != nil {
		return err
	}
	l.plan.Succeeded(c)
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

func activeMeta(s *session.MuxSession) string {
	if p, ok := activePath(s.Stats()); ok {
		return p.Meta.String()
	}
	return ""
}
