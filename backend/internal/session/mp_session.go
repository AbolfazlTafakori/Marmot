package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/fec"
	"marmot/internal/frame"
)

// v2 limits.
const (
	acceptBacklog  = 1024
	maxPeerStreams = 8192
	drainTimeout   = 2 * time.Second
	streamLinger   = 30 * time.Second
)

// errDuplicatePath means a join produced a path id already in use.
var errDuplicatePath = errors.New("session: duplicate path id")

// MPSession is session v2: a multipath packet session with its own stream
// layer (ADR-0013, spec §11). Every healthy path carries packets; lost
// frames are resent on another path; datagram paths add FEC.
type MPSession struct {
	id      crypto.SessionID
	peer    core.NodeID
	peerKey ed25519.PublicKey
	local   *crypto.Identity // initiator only: needed to join new paths
	localID core.NodeID      // initiator only
	role    Role
	caps    uint32
	cfg     ConnConfig
	log     *slog.Logger
	started time.Time

	mu         sync.Mutex
	paths      map[uint64]*mpPath
	order      []*mpPath
	ranks      map[uint64]int
	wakeList   atomic.Pointer[[]*mpPath]
	streams    map[uint32]*mpStream
	nextID     uint32
	peerClosed rangeSet // ids of peer streams that were opened and freed
	peerOpen   int
	acceptQ    chan *mpStream

	sendQ, vipQ []*mpStream // streams with bytes never sent
	retxQ       []*mpStream // streams with lost bytes
	ctrlQ       []ctrlItem
	dupQ        []dupItem
	maxDataPend bool

	sendMax   uint64 // the peer's MAX_DATA
	sentNew   uint64 // stream bytes sent at least once
	recvMax   uint64 // our MAX_DATA
	recvTotal uint64 // highest offsets received, summed over streams
	consumed  uint64 // bytes read or discarded, summed over streams
	written   uint64 // bytes written by callers
	delivered uint64 // bytes read by callers

	fecEnc   fec.Encoder
	fecDec   fec.Decoder
	fecTimer *time.Timer
	fecArmed bool
	fecNext  int
	fecSym   []byte
	rframe   frame.Frame // reader scratch, used under mu

	freeSent []*sentPacket

	closed      bool
	closeErr    error
	closeCode   uint16
	notifyPeer  bool
	resumeTimer *time.Timer

	done chan struct{}
	wg   sync.WaitGroup
}

var _ acceptedSession = (*MPSession)(nil)

func newMPSession(cfg ConnConfig, role Role, id crypto.SessionID, peer core.NodeID,
	peerKey ed25519.PublicKey, caps uint32) *MPSession {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &MPSession{
		id: id, peer: peer, peerKey: peerKey, role: role, caps: caps, cfg: cfg, log: log,
		started: time.Now(),
		paths:   map[uint64]*mpPath{}, streams: map[uint32]*mpStream{},
		acceptQ: make(chan *mpStream, acceptBacklog),
		sendMax: sessionWindow, recvMax: sessionWindow,
		done: make(chan struct{}),
	}
	s.nextID = 2
	if role == Initiator {
		s.nextID = 1
	}
	s.fecEnc.SetParams(cfg.FECData, cfg.FECParity)
	s.wakeList.Store(&[]*mpPath{})
	s.wg.Add(1)
	go s.housekeeping()
	return s
}

// shutdown closes the session. Each path writer sends CLOSE (when
// notifyPeer) and closes its path; closeGrace bounds a stuck write.
func (s *MPSession) shutdown(err error, code uint16, notifyPeer bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.closeErr, s.closeCode, s.notifyPeer = true, err, code, notifyPeer
	if s.resumeTimer != nil {
		s.resumeTimer.Stop()
		s.resumeTimer = nil
	}
	if s.fecTimer != nil {
		s.fecTimer.Stop()
	}
	paths := slices.Clone(s.order)
	for _, st := range s.streams {
		signal(st.readable)
		signal(st.writable)
	}
	// Counted before done closes: the session's goroutines still hold the
	// count above zero, so a concurrent Close cannot be in Wait at zero.
	s.wg.Add(1)
	s.mu.Unlock()
	close(s.done)
	s.wakeWriters()
	t := time.AfterFunc(closeGrace, func() {
		for _, p := range paths {
			_ = p.conn.Close()
		}
	})
	go func() {
		defer s.wg.Done()
		for _, p := range paths {
			<-p.gone
		}
		t.Stop()
	}()
}

// Close implements Session: it tells the peer and waits for every
// goroutine of the session.
func (s *MPSession) Close() error {
	s.shutdown(ErrClosed, frame.CloseShutdown, true)
	s.wg.Wait()
	return nil
}

// revoke implements acceptedSession.
func (s *MPSession) revoke() { s.shutdown(errors.New("peer revoked"), frame.CloseRevoked, true) }

// ID returns the session identifier.
func (s *MPSession) ID() crypto.SessionID { return s.id }

// Peer returns the configured id of the peer node.
func (s *MPSession) Peer() core.NodeID { return s.peer }

// PeerKey returns the authenticated key of the peer.
func (s *MPSession) PeerKey() ed25519.PublicKey { return s.peerKey }

// Role tells whether this node dialed the session.
func (s *MPSession) Role() Role { return s.role }

// Caps returns the negotiated capability bits.
func (s *MPSession) Caps() uint32 { return s.caps }

// Version returns 2.
func (s *MPSession) Version() int { return 2 }

// Started returns when the session was established.
func (s *MPSession) Started() time.Time { return s.started }

// Done is closed when the session ends.
func (s *MPSession) Done() <-chan struct{} { return s.done }

// Err returns why the session ended, or nil while it is open.
func (s *MPSession) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// NumStreams returns the number of streams not yet freed.
func (s *MPSession) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// Stats implements PeerSession. Ready means a path can carry data.
func (s *MPSession) Stats() ConnStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs := ConnStats{SentOff: s.written, AckedOff: s.written, RecvOff: s.delivered}
	cs.FECData, cs.FECParity = s.fecEnc.Params()
	for i, p := range s.order {
		cs.Paths = append(cs.Paths, p.info(i == 0 && p.healthy()))
		if p.healthy() {
			cs.Ready = true
		}
	}
	return cs
}

// Retire drains path id: it takes no new data and closes once what it
// carries is acknowledged. The caller joins a replacement first. It
// reports whether the path was there to retire.
func (s *MPSession) Retire(id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.paths[id]
	if p == nil || p.draining || p.dead {
		return false
	}
	p.draining, p.drainSince = true, time.Now()
	s.reorderLocked()
	signal(p.wake)
	return true
}

// Tune implements PeerSession.
func (s *MPSession) Tune(t Tuning) {
	s.mu.Lock()
	s.ranks = t.Ranks
	s.reorderLocked()
	s.fecEnc.SetParams(t.FECData, t.FECParity)
	s.mu.Unlock()
	s.wakeWriters()
}

// OpenStream implements Session.
func (s *MPSession) OpenStream(ctx context.Context, h frame.StreamHeader) (Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hdr, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		return nil, err
	}
	st := newMPStream(s, s.nextID, true)
	st.vip = h.Class == core.ClassVIP
	s.nextID += 2
	s.streams[st.id] = st
	s.mu.Unlock()
	if _, err := st.Write(hdr); err != nil {
		st.reset(0)
		return nil, fmt.Errorf("write stream header: %w", err)
	}
	return &openedStream{st: st}, nil
}

// AcceptStream implements Session.
func (s *MPSession) AcceptStream(ctx context.Context) (Stream, frame.StreamHeader, error) {
	var st *mpStream
	select {
	case st = <-s.acceptQ:
	case <-ctx.Done():
		return nil, frame.StreamHeader{}, ctx.Err()
	case <-s.done:
		return nil, frame.StreamHeader{}, fmt.Errorf("accept stream: %w", s.Err())
	}
	_ = st.SetReadDeadline(time.Now().Add(headerTimeout))
	h, err := frame.ReadStreamHeader(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		st.reset(0)
		return nil, h, fmt.Errorf("read stream header: %w", err)
	}
	s.mu.Lock()
	st.vip = h.Class == core.ClassVIP
	s.mu.Unlock()
	return st, h, nil
}
