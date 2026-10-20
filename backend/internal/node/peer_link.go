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
	"marmot/internal/session"
	"marmot/internal/transport"
)

const (
	dialTimeout    = 10 * time.Second
	maintainEvery  = 2 * time.Second
	minRedialDelay = time.Second
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
	log            *slog.Logger
}

// peerLink keeps one outbound session to a peer alive: it dials, keeps
// hot-standby paths joined, rotates paths make-before-break, and redials
// with backoff when the session ends. In Phase 2 the mesh path manager
// takes this role.
type peerLink struct {
	deps  linkDeps
	cfg   config.Peer
	id    core.NodeID
	key   ed25519.PublicKey
	cands []candidate
	next  int // round-robin cursor; owned by run

	mu   sync.Mutex
	sess *session.MuxSession

	wake   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
}

func startLink(deps linkDeps, p config.Peer, key ed25519.PublicKey, cands []candidate) *peerLink {
	ctx, cancel := context.WithCancel(context.Background())
	l := &peerLink{
		deps: deps, cfg: p, id: core.NodeID(p.ID), key: key, cands: cands,
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

func (l *peerLink) kick() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *peerLink) run(ctx context.Context) {
	defer close(l.done)
	if len(l.cands) == 0 {
		return // inbound-only peer: it dials us
	}
	delay := minRedialDelay
	for ctx.Err() == nil {
		s := l.establish(ctx)
		if s == nil {
			if !sleepCtx(ctx, delay) {
				return
			}
			delay = min(2*delay, maxRedialDelay)
			continue
		}
		delay = minRedialDelay
		l.setSession(s)
		l.deps.log.Info("session up")
		l.deps.events.publish(EventPeerState, map[string]any{"peer": l.id, "state": "up"})
		l.deps.serve(s)
		l.maintain(ctx, s)
		l.setSession(nil)
		_ = s.Close()
		l.deps.log.Info("session down", "err", s.Err())
		l.deps.events.publish(EventPeerState, map[string]any{"peer": l.id, "state": "down"})
	}
}

// establish tries each candidate once, round robin, and returns the first
// session that comes up.
func (l *peerLink) establish(ctx context.Context) *session.MuxSession {
	for range l.cands {
		c := l.pick(nil)
		conn, meta, err := l.dial(ctx, c)
		if err != nil {
			l.deps.log.Debug("dial failed", "via", c.key(), "err", err)
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
			l.deps.log.Warn("handshake failed", "via", meta, "err", err)
			continue
		}
		return s
	}
	return nil
}

func (l *peerLink) dial(ctx context.Context, c candidate) (transport.Conn, session.PathMeta, error) {
	tr, err := transport.Get(c.transport)
	if err != nil {
		return nil, session.PathMeta{}, err
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := tr.Dial(dctx, transport.Endpoint{Addr: c.remote, Options: c.options}, c.local)
	if err != nil {
		return nil, session.PathMeta{}, err
	}
	meta := session.PathMeta{Transport: c.transport, Local: conn.LocalAddr().String(), Remote: c.remote.String()}
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

// maintain keeps standbys filled and rotates paths until the session ends
// or the link stops.
func (l *peerLink) maintain(ctx context.Context, s *session.MuxSession) {
	t := time.NewTicker(maintainEvery)
	defer t.Stop()
	lastRotate, baseBytes := time.Now(), sessionBytes(s)
	for {
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
// preferring routes not already in use.
func (l *peerLink) fillStandby(ctx context.Context, s *session.MuxSession) {
	for tries := 0; tries < len(l.cands); tries++ {
		st := s.Stats()
		if len(st.Paths) >= 1+l.deps.standby || ctx.Err() != nil {
			return
		}
		if err := l.join(ctx, s, inUse(st), false); err != nil {
			l.deps.log.Debug("standby join failed", "err", err)
		}
	}
}

// rotate replaces the active path with a fresh one (new keys, ideally a
// different route) before closing the old one.
func (l *peerLink) rotate(ctx context.Context, s *session.MuxSession) {
	if err := l.join(ctx, s, inUse(s.Stats()), true); err != nil {
		l.deps.log.Warn("rotation failed", "err", err)
		return
	}
	l.deps.log.Debug("path rotated")
	l.deps.events.publish(EventRotation, map[string]any{"peer": l.id})
}

func (l *peerLink) join(ctx context.Context, s *session.MuxSession, used map[string]bool, rotate bool) error {
	c := l.pick(used)
	conn, meta, err := l.dial(ctx, c)
	if err != nil {
		return err
	}
	jctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return s.Join(jctx, conn, meta, rotate)
}

// pick returns the next candidate whose route is not in used, or simply
// the next one when every route is in use.
func (l *peerLink) pick(used map[string]bool) candidate {
	for i := 0; i < len(l.cands); i++ {
		c := l.cands[(l.next+i)%len(l.cands)]
		if !used[routeKey(c.transport, c.remote.String())] {
			l.next += i + 1
			return c
		}
	}
	c := l.cands[l.next%len(l.cands)]
	l.next++
	return c
}

func inUse(st session.ConnStats) map[string]bool {
	m := make(map[string]bool, len(st.Paths))
	for i := range st.Paths {
		m[routeKey(st.Paths[i].Meta.Transport, st.Paths[i].Meta.Remote)] = true
	}
	return m
}

func routeKey(transport, remote string) string { return transport + "|" + remote }

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
