package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/transport"
)

// AcceptorConfig configures the inbound side.
type AcceptorConfig struct {
	Local *crypto.Identity
	Peers *PeerKeys
	Caps  uint32
	Conn  ConnConfig // Role is set to Responder
	// OnSession receives every new inbound session. It must not block.
	OnSession func(*MuxSession)
	Logger    *slog.Logger
}

// Acceptor authenticates inbound paths and sorts them into sessions: a
// Hello without JOIN starts a session, a JOIN adds a path to one.
type Acceptor struct {
	cfg       AcceptorConfig
	log       *slog.Logger
	peers     atomic.Pointer[PeerKeys]
	responder *crypto.Responder

	mu       sync.Mutex
	sessions map[crypto.SessionID]*MuxSession
	closed   bool
	wg       sync.WaitGroup
}

// NewAcceptor creates an acceptor.
func NewAcceptor(cfg AcceptorConfig) (*Acceptor, error) {
	if cfg.Local == nil || cfg.Peers == nil || cfg.OnSession == nil {
		return nil, errors.New("session: acceptor needs identity, peers and OnSession")
	}
	cfg.Conn.Role = Responder
	if err := cfg.Conn.validate(); err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	a := &Acceptor{cfg: cfg, log: log, sessions: make(map[crypto.SessionID]*MuxSession)}
	a.peers.Store(cfg.Peers)
	a.responder = crypto.NewResponder(cfg.Local, func(x []byte) (ed25519.PublicKey, bool) {
		return a.peers.Load().lookupX25519(x)
	})
	return a, nil
}

// SetPeers replaces the peer directory. Sessions of peers that are gone,
// or whose key changed, are closed at once (revocation).
func (a *Acceptor) SetPeers(k *PeerKeys) {
	a.peers.Store(k)
	a.mu.Lock()
	var revoked []*MuxSession
	for _, s := range a.sessions {
		if pub, ok := k.KeyOf(s.peer); !ok || !pub.Equal(s.peerKey) {
			revoked = append(revoked, s)
		}
	}
	a.mu.Unlock()
	for _, s := range revoked {
		a.log.Info("peer revoked; closing session", "peer", s.peer)
		s.conn.shutdown(errors.New("peer revoked"), frame.CloseRevoked, true)
	}
}

// Handle authenticates one accepted connection and attaches it to a
// session. It consumes conn and returns when the handshake is done.
func (a *Acceptor) Handle(ctx context.Context, conn transport.Conn, meta PathMeta) error {
	peers := a.peers.Load()
	var (
		join   *MuxSession
		peerID core.NodeID
	)
	done := boundHandshake(ctx, conn)
	acc, err := a.responder.Respond(conn, func(pub ed25519.PublicKey, h crypto.Hello) crypto.Welcome {
		peerID, _ = peers.IDOf(pub)
		a.mu.Lock()
		defer a.mu.Unlock()
		existing := a.sessions[h.SessionID]
		if h.Flags&(crypto.FlagJoin|crypto.FlagRotate) != 0 {
			// A path may only join a session of the same peer.
			if existing == nil || !existing.peerKey.Equal(pub) {
				return crypto.Welcome{Status: crypto.StatusUnknownSession}
			}
			join = existing
			return crypto.Welcome{Status: crypto.StatusOK, Caps: existing.caps}
		}
		if existing != nil || a.closed {
			return crypto.Welcome{Status: crypto.StatusRejected}
		}
		return crypto.Welcome{Status: crypto.StatusOK, Caps: h.Caps & a.cfg.Caps}
	})
	done()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("accept %s: %w", meta, err)
	}
	fc := frame.NewConn(conn, acc.Ciphers)
	if acc.Hello.NodeID != peerID {
		a.log.Warn("peer claims a different node id", "peer", peerID, "claimed", acc.Hello.NodeID)
	}
	if join != nil {
		_, err := join.conn.AddPath(fc, meta)
		return err
	}
	return a.startSession(acc, fc, peerID, meta)
}

func (a *Acceptor) startSession(acc crypto.Accepted, fc *frame.Conn, peerID core.NodeID, meta PathMeta) error {
	rc, err := NewResumableConn(a.cfg.Conn)
	if err != nil {
		_ = fc.Close()
		return err
	}
	if _, err := rc.AddPath(fc, meta); err != nil {
		_ = rc.Close()
		return err
	}
	s, err := newMuxSession(rc, Responder, acc.Hello.SessionID, peerID, acc.PeerKey, acc.Hello.Caps&a.cfg.Caps)
	if err != nil {
		_ = rc.Close()
		return err
	}
	a.mu.Lock()
	if a.closed || a.sessions[s.id] != nil {
		a.mu.Unlock()
		_ = s.Close()
		return errors.New("session: duplicate session id or acceptor closed")
	}
	a.sessions[s.id] = s
	a.wg.Add(1)
	a.mu.Unlock()
	go func() {
		defer a.wg.Done()
		<-s.Done()
		a.mu.Lock()
		if a.sessions[s.id] == s {
			delete(a.sessions, s.id)
		}
		a.mu.Unlock()
	}()
	a.log.Info("inbound session", "peer", peerID, "via", meta)
	a.cfg.OnSession(s)
	return nil
}

// Sessions returns the open inbound sessions.
func (a *Acceptor) Sessions() []*MuxSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*MuxSession, 0, len(a.sessions))
	for _, s := range a.sessions {
		out = append(out, s)
	}
	return out
}

// Close closes every inbound session and waits for them.
func (a *Acceptor) Close() error {
	a.mu.Lock()
	a.closed = true
	all := make([]*MuxSession, 0, len(a.sessions))
	for _, s := range a.sessions {
		all = append(all, s)
	}
	a.mu.Unlock()
	for _, s := range all {
		_ = s.Close()
	}
	a.wg.Wait()
	return nil
}
