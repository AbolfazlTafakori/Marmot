package session

import (
	"context"
	"crypto/ed25519"
	"time"

	"marmot/internal/crypto"
	"marmot/internal/transport"
)

// HandshakeTimeout bounds one path handshake (spec §3).
const HandshakeTimeout = 10 * time.Second

// deadliner is implemented by every stream transport we ship; a transport
// without deadlines still works, its handshake is just not bounded here.
type deadliner interface {
	SetDeadline(t time.Time) error
}

// boundHandshake applies HandshakeTimeout (or ctx's earlier deadline) to
// conn, and aborts at once when ctx is cancelled. The returned function
// clears the deadline and must be called when the handshake ends.
func boundHandshake(ctx context.Context, conn transport.Conn) func() {
	d, ok := conn.(deadliner)
	if !ok {
		return func() {}
	}
	deadline := time.Now().Add(HandshakeTimeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(deadline) {
		deadline = cd
	}
	_ = d.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = d.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		_ = d.SetDeadline(time.Time{})
	}
}

// clientHandshake runs the initiator handshake on conn and returns the
// path keys; the caller builds the record layer. On error conn is closed.
func clientHandshake(ctx context.Context, conn transport.Conn, local *crypto.Identity,
	peer ed25519.PublicKey, hello crypto.Hello) (crypto.CipherPair, crypto.Welcome, error) {
	done := boundHandshake(ctx, conn)
	keys, w, err := crypto.Initiate(conn, local, peer, hello)
	done()
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return keys, w, ctx.Err()
		}
		return keys, w, err
	}
	return keys, w, nil
}
