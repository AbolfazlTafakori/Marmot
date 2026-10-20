// Package session carries many user streams between two nodes over one
// authenticated association that survives path changes.
//
// v1 (this package today) is smux over a ResumableConn: one active path,
// hot standbys, and make-before-break failover and rotation
// (docs/adr/0003-session-layer-evolution.md, docs/spec/frame.md §5).
package session

import (
	"context"
	"io"
	"time"

	"marmot/internal/frame"
)

// Session is the contract the ingress and egress layers use. v2 will
// implement the same interface.
type Session interface {
	// OpenStream opens a stream and sends h. The receiver's reply byte is
	// read lazily: the first Read returns a *ReplyError if the receiver
	// refused, so opening a stream costs no round trip.
	OpenStream(ctx context.Context, h frame.StreamHeader) (Stream, error)
	// AcceptStream returns the next stream opened by the peer and its
	// header. The caller must write one reply byte (frame.Reply*) before
	// any data.
	AcceptStream(ctx context.Context) (Stream, frame.StreamHeader, error)
	Close() error
}

// Stream is one multiplexed user connection.
type Stream interface {
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
