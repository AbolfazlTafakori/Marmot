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
	serve          func(session.PeerSession) // starts the stream accept loop
	relayVias      func(target core.NodeID) []core.NodeID
	dialRelay      func(ctx context.Context, via, target core.NodeID) (transport.Conn, error)
	reportDial     func(c mesh.Candidate, ok bool) // for the controller
	log            *slog.Logger
}

// peerLink keeps one outbound session to a peer alive: it dials, keeps
// hot-standby paths joined, rotates paths make-before-break, and redials
// when the session ends. Which route to try comes from the peer's
// mesh.Planner: diverse routes first, failed ones in quarantine, relayed
// routes only while no direct path is up (ADR-0011, ADR-0012).
type peerLink struct {
	deps   linkDeps
	cfg    config.Peer
	id     core.NodeID
	key    ed25519.PublicKey
	routes linkRoutes

	// planMu guards plan and relayTurn: run and the relay watcher of a v2
	// session both choose routes.
	planMu    sync.Mutex
	plan      *mesh.Planner
	relayTurn bool // whether a relayed route goes first next time

	mu      sync.Mutex
	sess    session.PeerSession
	pref    func(mesh.Candidate) int // from the controller; applied by run
	replace []uint64                 // lossy paths the controller wants replaced
	hops    map[string]time.Duration // hop interval by path transport|remote

	wake      chan struct{} // wakes maintain
	relayWake chan struct{} // wakes the relay watcher
	cancel    context.CancelFunc
	done      chan struct{}
}

func startLink(deps linkDeps, p config.Peer, key ed25519.PublicKey, routes linkRoutes) *peerLink {
	ctx, cancel := context.WithCancel(context.Background())
	l := &peerLink{
		deps: deps, cfg: p, id: core.NodeID(p.ID), key: key, routes: routes,
		plan: mesh.NewPlanner(routes.build(time.Now()), nil),
		wake: make(chan struct{}, 1), relayWake: make(chan struct{}, 1), cancel: cancel, done: make(chan struct{}),
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
func (l *peerLink) session() session.PeerSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sess
}

func (l *peerLink) setSession(s session.PeerSession) {
	l.mu.Lock()
	l.sess = s
	l.mu.Unlock()
}

// setPreference hands the planner the controller's candidate order; run
// applies it before its next choice.
func (l *peerLink) setPreference(pref func(mesh.Candidate) int) {
	l.mu.Lock()
	l.pref = pref
	l.mu.Unlock()
}

// requestReplace asks the link to replace a lossy path of its session
// make-before-break.
func (l *peerLink) requestReplace(pathID uint64) {
	l.mu.Lock()
	if len(l.replace) < 8 {
		l.replace = append(l.replace, pathID)
	}
	l.mu.Unlock()
	l.kick()
}

func (l *peerLink) takeReplace() []uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.replace
	l.replace = nil
	return out
}

// kick makes the link look at its paths now, e.g. because a relay came up.
func (l *peerLink) kick() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
	select {
	case l.relayWake <- struct{}{}:
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
		stopWatch := l.watchRelay(ctx, s)
		l.maintain(ctx, s)
		stopWatch()
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
	var vias []core.NodeID
	if !hasDirect(inUse) {
		vias = l.deps.relayVias(l.id) // takes node locks: not under planMu
	}
	l.planMu.Lock()
	defer l.planMu.Unlock()
	l.applyPreferenceLocked()
	if hasDirect(inUse) {
		return l.plan.Next(inUse, mesh.Direct)
	}
	l.plan.SetRelays(vias)
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

// applyPreferenceLocked hands the planner the controller's latest
// preference; the caller holds planMu.
func (l *peerLink) applyPreferenceLocked() {
	l.mu.Lock()
	pref := l.pref
	l.mu.Unlock()
	l.plan.SetPreference(pref)
}

// nextOf asks the planner for a route of the given kinds only.
func (l *peerLink) nextOf(inUse []mesh.Route, kinds mesh.Kinds, vias []core.NodeID) (mesh.Candidate, bool) {
	l.planMu.Lock()
	defer l.planMu.Unlock()
	l.applyPreferenceLocked()
	if kinds&mesh.Relayed != 0 {
		l.plan.SetRelays(vias)
	}
	c, _, ok := l.plan.Next(inUse, kinds)
	return c, ok
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
func (l *peerLink) establish(ctx context.Context) (session.PeerSession, time.Duration) {
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
		cc.OnPathSuspect = l.onPathSuspect
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
		l.succeeded(c)
		l.noteHop(meta, c.Hop)
		return s, 0
	}
	return nil, 0
}

func (l *peerLink) fail(c mesh.Candidate, what string, err error) {
	l.planMu.Lock()
	d := l.plan.Failed(c)
	l.planMu.Unlock()
	if l.deps.reportDial != nil {
		l.deps.reportDial(c, false)
	}
	l.deps.log.Debug(what, "via", c.Key(), "err", err, "quarantine", d)
}

func (l *peerLink) succeeded(c mesh.Candidate) {
	l.planMu.Lock()
	l.plan.Succeeded(c)
	l.planMu.Unlock()
	if l.deps.reportDial != nil {
		l.deps.reportDial(c, true)
	}
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

// onPathSuspect reacts at once to a v2 path that stopped being
// acknowledged: the relay watcher may need to act, and a leading path
// going suspect is v2's failover.
func (l *peerLink) onPathSuspect(info session.PathInfo) {
	if info.Active {
		l.deps.events.publish(EventFailover, map[string]any{
			"peer": l.id, "path": info.ID, "transport": info.Meta.Transport,
			"remote": info.Meta.Remote, "state": "suspect",
		})
	}
	l.kick()
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
