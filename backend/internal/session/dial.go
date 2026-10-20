package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/transport"
)

// DialConfig describes the outbound side of a session.
type DialConfig struct {
	Local   *crypto.Identity
	LocalID core.NodeID
	Peer    core.NodeID
	PeerKey ed25519.PublicKey
	Caps    uint32
	Conn    ConnConfig // Role is set to Initiator
}

// Dial establishes a new session over conn, which becomes its first path.
// The session is v2 when cfg.Caps offers CapMultipath and the peer keeps
// it, else v1 (ADR-0013 §1). More paths are added with Join. conn is
// consumed.
func Dial(ctx context.Context, cfg DialConfig, conn transport.Conn, meta PathMeta) (PeerSession, error) {
	var id crypto.SessionID
	if _, err := rand.Read(id[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("session id: %w", err)
	}
	hello := crypto.Hello{SessionID: id, NodeID: cfg.LocalID, Caps: cfg.Caps}
	keys, w, err := clientHandshake(ctx, conn, cfg.Local, cfg.PeerKey, hello)
	if err != nil {
		return nil, fmt.Errorf("dial %s via %s: %w", cfg.Peer, meta, err)
	}
	cc := cfg.Conn
	cc.Role = Initiator
	if w.Caps&crypto.CapMultipath != 0 {
		s := newMPSession(cc, Initiator, id, cfg.Peer, cfg.PeerKey, w.Caps)
		s.local, s.localID = cfg.Local, cfg.LocalID
		if _, err := s.addPath(conn, keys, meta); err != nil {
			_ = s.Close()
			return nil, err
		}
		return s, nil
	}
	rc, err := NewResumableConn(cc)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := rc.AddPath(frame.NewConn(conn, keys), meta); err != nil {
		_ = rc.Close()
		return nil, err
	}
	s, err := newMuxSession(rc, Initiator, id, cfg.Peer, cfg.PeerKey, w.Caps)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	s.local, s.localID = cfg.Local, cfg.LocalID
	return s, nil
}
