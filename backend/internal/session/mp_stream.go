package session

import (
	"errors"
	"io"
	"os"
	"time"
)

// Flow-control windows of v2 (ADR-0013 §8), the same sizes v1 gives smux.
const (
	streamWindow  = 2 << 20
	sessionWindow = 16 << 20
)

// Stream errors of v2.
var (
	ErrStreamReset   = errors.New("session: stream reset")
	ErrStreamStopped = errors.New("session: peer stopped reading the stream")
)

// mpStream is one stream of a v2 session. Each direction ends on its own
// (spec §11.3): the send side with an acknowledged FIN or RESET, the
// receive side when FIN is reached or RESET arrives. All state is guarded
// by the session's mutex; Read and Write wait on the signal channels.
type mpStream struct {
	s     *MPSession
	id    uint32
	local bool // opened by this side
	vip   bool

	readable, writable chan struct{}
	rdl, wdl           *deadline

	// Send side: sbuf holds [ackBase, writeOff).
	sbuf         *ring
	ackBase      uint64
	writeOff     uint64
	sentOff      uint64 // first byte never sent
	acked        rangeSet
	retx         rangeSet
	retxAvoid    uint64 // path the lost bytes were last sent on
	sendMax      uint64 // the peer's limit for this stream
	finWanted    bool   // Close: FIN after writeOff
	finSent      bool
	finAcked     bool
	finRetx      bool
	stopped      bool // the peer asked us to stop sending
	resetOut     bool // we abandoned the send side
	resetPending bool // our RESET is not acknowledged yet
	resetQd      bool // our RESET is queued
	resetCode    uint64
	queued       bool // in the session's send queue
	retxQd       bool // in the session's retransmit queue

	// Receive side.
	rbuf        recvBuf
	readOff     uint64 // bytes read or discarded
	recvHigh    uint64 // highest offset received
	finOff      uint64
	finKnown    bool // final size known, from FIN or RESET
	resetIn     bool // the peer abandoned its send side
	recvMax     uint64
	readClosed  bool // the caller closed; incoming bytes are discarded
	maxPending  bool // MAX_STREAM_DATA queued
	stopPending bool // STOP queued

	closedAt time.Time
	freed    bool
}

func newMPStream(s *MPSession, id uint32, local bool) *mpStream {
	return &mpStream{
		s: s, id: id, local: local,
		readable: make(chan struct{}, 1), writable: make(chan struct{}, 1),
		rdl: newDeadline(), wdl: newDeadline(),
		sbuf:    newRing(4<<10, streamWindow),
		sendMax: streamWindow, recvMax: streamWindow,
		rbuf: recvBuf{max: streamWindow},
	}
}

// Read implements io.Reader.
func (st *mpStream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s := st.s
	for {
		s.mu.Lock()
		switch {
		case st.readClosed:
			s.mu.Unlock()
			return 0, io.ErrClosedPipe
		case st.resetIn:
			s.mu.Unlock()
			return 0, ErrStreamReset
		}
		if n := st.rbuf.read(st.readOff, b); n > 0 {
			st.readOff += uint64(n)
			wake := s.consumedLocked(st, n, true)
			s.maybeFreeLocked(st)
			s.mu.Unlock()
			if wake {
				s.wakeWriters()
			}
			return n, nil
		}
		if st.finKnown && st.readOff == st.finOff {
			s.maybeFreeLocked(st)
			s.mu.Unlock()
			return 0, io.EOF
		}
		if s.closed {
			err := s.closeErr
			s.mu.Unlock()
			return 0, err
		}
		s.mu.Unlock()
		select {
		case <-st.readable:
		case <-st.rdl.wait():
			return 0, os.ErrDeadlineExceeded
		case <-s.done:
		}
	}
}

// Write implements io.Writer. It blocks while the stream's send buffer is
// full; the buffer drains as the peer acknowledges.
func (st *mpStream) Write(b []byte) (int, error) {
	s := st.s
	n := 0
	for n < len(b) {
		s.mu.Lock()
		if err := st.writeErrLocked(); err != nil {
			s.mu.Unlock()
			return n, err
		}
		if st.sbuf.Free() > 0 {
			k := st.sbuf.Write(b[n:])
			st.writeOff += uint64(k)
			s.written += uint64(k)
			n += k
			s.queueSendLocked(st)
			s.mu.Unlock()
			s.wakeWriters()
			continue
		}
		s.mu.Unlock()
		select {
		case <-st.writable:
		case <-st.wdl.wait():
			return n, os.ErrDeadlineExceeded
		case <-s.done:
		}
	}
	return n, nil
}

func (st *mpStream) writeErrLocked() error {
	switch {
	case st.s.closed:
		return st.s.closeErr
	case st.stopped:
		return ErrStreamStopped
	case st.resetOut:
		return ErrStreamReset
	case st.finWanted:
		return io.ErrClosedPipe
	}
	return nil
}

// Close ends both directions: data already written is still delivered,
// then FIN; if the peer's direction is still open it is asked to stop
// (ADR-0013 §9).
func (st *mpStream) Close() error {
	s := st.s
	s.mu.Lock()
	if !st.finWanted && !st.resetOut {
		st.finWanted = true
		s.queueSendLocked(st)
	}
	s.closeRecvLocked(st)
	st.closedAt = time.Now()
	s.maybeFreeLocked(st)
	s.mu.Unlock()
	signal(st.readable)
	signal(st.writable)
	s.wakeWriters()
	return nil
}

// reset aborts both directions: RESET for ours, STOP for the peer's.
func (st *mpStream) reset(code uint64) {
	s := st.s
	s.mu.Lock()
	s.resetSendLocked(st, code)
	s.closeRecvLocked(st)
	st.closedAt = time.Now()
	s.maybeFreeLocked(st)
	s.mu.Unlock()
	signal(st.readable)
	signal(st.writable)
	s.wakeWriters()
}

// SetReadDeadline implements Stream.
func (st *mpStream) SetReadDeadline(t time.Time) error {
	st.rdl.set(t)
	return nil
}

// SetWriteDeadline implements Stream.
func (st *mpStream) SetWriteDeadline(t time.Time) error {
	st.wdl.set(t)
	return nil
}

// sendDone reports whether the send side has ended for both peers.
func (st *mpStream) sendDone() bool {
	return st.finAcked || (st.resetOut && !st.resetPending)
}

// recvDone reports whether the receive side has ended: every byte up to
// the final size was read or discarded, or the peer reset it.
func (st *mpStream) recvDone() bool {
	return st.resetIn || (st.finKnown && st.readOff == st.finOff)
}

// sendAborted reports whether nothing more is sent on the stream.
func (st *mpStream) sendAborted() bool { return st.resetOut || st.stopped }

// canSendNew reports whether the stream can send bytes (or a FIN) it
// never sent, within its own flow-control limit.
func (st *mpStream) canSendNew() bool {
	if st.sendAborted() {
		return false
	}
	if st.sentOff < st.writeOff && st.sentOff < st.sendMax {
		return true
	}
	return st.finWanted && !st.finSent && st.sentOff == st.writeOff
}

// hasRetx reports whether the stream has lost bytes (or a FIN) to resend.
func (st *mpStream) hasRetx() bool {
	return !st.sendAborted() && (!st.retx.empty() || st.finRetx)
}
