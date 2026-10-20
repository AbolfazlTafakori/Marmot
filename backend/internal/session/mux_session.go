package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/transport"
)

// headerTimeout bounds how long an accepted stream may take to send its
// header.
const headerTimeout = 10 * time.Second

// smuxConfig sizes windows for long fat links (Iran to Europe is ~100 ms):
// the default 64 KiB per-stream window would cap a stream at ~640 KB/s.
// smux keepalive is off; path liveness is the ResumableConn's job, and a
// failover pause must not look like a dead session.
func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveDisabled = true
	c.MaxFrameSize = 32 << 10
	c.MaxReceiveBuffer = 16 << 20
	c.MaxStreamBuffer = 2 << 20
	return c
}

// MuxSession is the v1 Session: smux over a ResumableConn.
type MuxSession struct {
	id      crypto.SessionID
	peer    core.NodeID
	peerKey ed25519.PublicKey
	local   *crypto.Identity // initiator only: needed to join new paths
	localID core.NodeID      // initiator only
	role    Role
	caps    uint32
	conn    *ResumableConn
	mux     *smux.Session
	started time.Time

	closeOnce sync.Once
	wg        sync.WaitGroup
}

var _ Session = (*MuxSession)(nil)

func newMuxSession(conn *ResumableConn, role Role, id crypto.SessionID, peer core.NodeID,
	peerKey ed25519.PublicKey, caps uint32) (*MuxSession, error) {
	var mux *smux.Session
	var err error
	if role == Initiator {
		mux, err = smux.Client(conn, smuxConfig())
	} else {
		mux, err = smux.Server(conn, smuxConfig())
	}
	if err != nil {
		return nil, fmt.Errorf("session mux: %w", err)
	}
	s := &MuxSession{id: id, peer: peer, peerKey: peerKey, role: role, caps: caps,
		conn: conn, mux: mux, started: time.Now()}
	// If either layer dies on its own, take the other one down too.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-conn.Done():
		case <-mux.CloseChan():
		}
		_ = mux.Close()
		conn.shutdown(ErrClosed, frame.CloseShutdown, true)
	}()
	return s, nil
}

// ID returns the session identifier.
func (s *MuxSession) ID() crypto.SessionID { return s.id }

// Peer returns the configured id of the peer node.
func (s *MuxSession) Peer() core.NodeID { return s.peer }

// PeerKey returns the authenticated key of the peer.
func (s *MuxSession) PeerKey() ed25519.PublicKey { return s.peerKey }

// Role tells whether this node dialed the session.
func (s *MuxSession) Role() Role { return s.role }

// Caps returns the negotiated capability bits.
func (s *MuxSession) Caps() uint32 { return s.caps }

// Started returns when the session was established.
func (s *MuxSession) Started() time.Time { return s.started }

// Done is closed when the session ends.
func (s *MuxSession) Done() <-chan struct{} { return s.conn.Done() }

// Err returns why the session ended, or nil while it is open.
func (s *MuxSession) Err() error { return s.conn.Err() }

// Stats returns path and byte counters.
func (s *MuxSession) Stats() ConnStats { return s.conn.Stats() }

// NumStreams returns the number of open streams.
func (s *MuxSession) NumStreams() int { return s.mux.NumStreams() }

// OpenStream implements Session.
func (s *MuxSession) OpenStream(ctx context.Context, h frame.StreamHeader) (Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hdr, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}
	st, err := s.mux.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	if _, err := st.Write(hdr); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("write stream header: %w", err)
	}
	return &openedStream{st: st}, nil
}

// AcceptStream implements Session.
func (s *MuxSession) AcceptStream(ctx context.Context) (Stream, frame.StreamHeader, error) {
	_ = s.mux.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { _ = s.mux.SetDeadline(time.Unix(1, 0)) })
	st, err := s.mux.AcceptStream()
	stop()
	if err != nil {
		if ctx.Err() != nil {
			return nil, frame.StreamHeader{}, ctx.Err()
		}
		return nil, frame.StreamHeader{}, fmt.Errorf("accept stream: %w", err)
	}
	_ = st.SetReadDeadline(time.Now().Add(headerTimeout))
	h, err := frame.ReadStreamHeader(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		_ = st.Close()
		return nil, h, fmt.Errorf("read stream header: %w", err)
	}
	return st, h, nil
}

// Join adds another path to this session (initiator only). With rotate,
// the new path replaces the active one make-before-break; otherwise it
// becomes a hot standby. conn is consumed.
func (s *MuxSession) Join(ctx context.Context, conn transport.Conn, meta PathMeta, rotate bool) error {
	if s.role != Initiator {
		_ = conn.Close()
		return ErrNotInitiator
	}
	flags := crypto.FlagJoin
	if rotate {
		flags |= crypto.FlagRotate
	}
	hello := crypto.Hello{Flags: flags, SessionID: s.id, NodeID: s.localID, Caps: s.caps}
	fc, _, err := clientHandshake(ctx, conn, s.local, s.peerKey, hello)
	if err != nil {
		return fmt.Errorf("join %s: %w", meta, err)
	}
	id, err := s.conn.AddPath(fc, meta)
	if err != nil {
		return err
	}
	if rotate {
		return s.conn.Promote(id, true)
	}
	return nil
}

// Close implements Session.
func (s *MuxSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.mux.Close()
		_ = s.conn.Close()
		s.wg.Wait()
	})
	return nil
}

// openedStream reads the receiver's reply byte before the first data.
// It wraps rather than embeds *smux.Stream so that smux's WriteTo is not
// promoted: io.Copy would use it and skip the reply byte.
type openedStream struct {
	st       *smux.Stream
	replied  bool
	replyErr error
}

func (s *openedStream) Write(b []byte) (int, error)        { return s.st.Write(b) }
func (s *openedStream) Close() error                       { return s.st.Close() }
func (s *openedStream) SetReadDeadline(t time.Time) error  { return s.st.SetReadDeadline(t) }
func (s *openedStream) SetWriteDeadline(t time.Time) error { return s.st.SetWriteDeadline(t) }

// ReplyError reports that the receiving node refused a stream.
type ReplyError struct{ Code byte }

func (e *ReplyError) Error() string {
	switch e.Code {
	case frame.ReplyRefused:
		return "stream refused by target"
	case frame.ReplyUnreachable:
		return "stream target unreachable"
	case frame.ReplyDenied:
		return "stream denied by policy"
	default:
		return fmt.Sprintf("stream rejected (code %d)", e.Code)
	}
}

func (s *openedStream) Read(b []byte) (int, error) {
	if err := s.readReply(); err != nil {
		return 0, err
	}
	return s.st.Read(b)
}

// readReply consumes the receiver's reply byte once; a refusal is kept
// and returned by every later Read.
func (s *openedStream) readReply() error {
	if s.replied {
		return s.replyErr
	}
	var r [1]byte
	if _, err := io.ReadFull(s.st, r[:]); err != nil {
		return err
	}
	s.replied = true
	if r[0] != frame.ReplyOK {
		s.replyErr = &ReplyError{Code: r[0]}
	}
	return s.replyErr
}

// AwaitReply waits for the receiver's answer before any data, for callers
// that must know the outcome first (the SOCKS5 inbound replies to its
// client only after the far side has connected). It must not run
// concurrently with Read.
func (s *openedStream) AwaitReply(ctx context.Context) error {
	if d, ok := ctx.Deadline(); ok {
		_ = s.st.SetReadDeadline(d)
		defer func() { _ = s.st.SetReadDeadline(time.Time{}) }()
	}
	return s.readReply()
}

// IsReplyError reports whether err is a refusal by the receiving node.
func IsReplyError(err error) bool {
	var re *ReplyError
	return errors.As(err, &re)
}
