package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"marmot/internal/core"
	"marmot/internal/crypto"
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

// Dial establishes a new session over conn, which becomes its first and
// active path. More paths are added with Join. conn is consumed.
func Dial(ctx context.Context, cfg DialConfig, conn transport.Conn, meta PathMeta) (*MuxSession, error) {
	var id crypto.SessionID
	if _, err := rand.Read(id[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("session id: %w", err)
	}
	hello := crypto.Hello{SessionID: id, NodeID: cfg.LocalID, Caps: cfg.Caps}
	fc, w, err := clientHandshake(ctx, conn, cfg.Local, cfg.PeerKey, hello)
	if err != nil {
		return nil, fmt.Errorf("dial %s via %s: %w", cfg.Peer, meta, err)
	}
	cc := cfg.Conn
	cc.Role = Initiator
	rc, err := NewResumableConn(cc)
	if err != nil {
		_ = fc.Close()
		return nil, err
	}
	if _, err := rc.AddPath(fc, meta); err != nil {
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
