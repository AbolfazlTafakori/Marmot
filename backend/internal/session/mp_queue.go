package session

import (
	"time"
)

// ctrlItem is a control frame owed to the peer. The value is read when the
// frame is built, so a resend always carries the latest one.
type ctrlItem struct {
	kind frameKind
	sid  uint32
}

// dupItem is a range of a VIP stream sent on origin that another path
// should send again (ADR-0013 §7).
type dupItem struct {
	sid    uint32
	off    uint64
	n      int
	fin    bool
	origin uint64
	at     time.Time
}

// repairItem is an FEC parity symbol waiting for its path.
type repairItem struct {
	group    uint32
	k, m, ix uint8
	parity   []byte
}

const (
	maxDupQueue    = 256
	maxRepairQueue = 64
	dupMaxAge      = 500 * time.Millisecond
)

// queueSendLocked puts st in the send queue if it can send new bytes.
func (s *MPSession) queueSendLocked(st *mpStream) {
	if st.queued || st.freed || !st.canSendNew() {
		return
	}
	st.queued = true
	if st.vip {
		s.vipQ = append(s.vipQ, st)
	} else {
		s.sendQ = append(s.sendQ, st)
	}
}

// queueRetxLocked puts st in the retransmit queue.
func (s *MPSession) queueRetxLocked(st *mpStream) {
	if st.retxQd || st.freed || !st.hasRetx() {
		return
	}
	st.retxQd = true
	s.retxQ = append(s.retxQ, st)
}

func (s *MPSession) queueCtrlLocked(it ctrlItem) {
	s.ctrlQ = append(s.ctrlQ, it)
}

// framesAckedLocked handles the acknowledgement of a packet's frames.
func (s *MPSession) framesAckedLocked(frames []sentFrame) {
	for i := range frames {
		f := &frames[i]
		st := s.streams[f.sid]
		if st == nil {
			continue
		}
		switch f.kind {
		case fkStream:
			s.streamAckedLocked(st, f.off, f.n, f.fin)
		case fkReset:
			st.resetPending = false
			s.maybeFreeLocked(st)
		}
	}
}

// streamAckedLocked records acknowledged bytes and frees the buffer below
// the lowest unacknowledged byte.
func (s *MPSession) streamAckedLocked(st *mpStream, off uint64, n int, fin bool) {
	if st.sendAborted() {
		return
	}
	end := off + uint64(n)
	if fin {
		st.finAcked, st.finRetx = true, false
	}
	if end > st.ackBase {
		st.acked.add(max(off, st.ackBase), end)
		st.retx.remove(off, end)
		if f, ok := st.acked.first(); ok && f.lo <= st.ackBase {
			st.sbuf.Discard(int(f.hi - st.ackBase))
			st.ackBase = f.hi
			st.acked.trimBelow(st.ackBase)
			signal(st.writable)
		}
	}
	s.maybeFreeLocked(st)
}

// framesLostLocked queues the frames of a lost packet again. avoid is the
// path they were lost on (0 = none), so a resend prefers another one.
func (s *MPSession) framesLostLocked(frames []sentFrame, avoid uint64) {
	for i := range frames {
		f := &frames[i]
		st := s.streams[f.sid]
		switch f.kind {
		case fkStream:
			if st == nil || st.sendAborted() {
				continue
			}
			lo, hi := max(f.off, st.ackBase), f.off+uint64(f.n)
			if lo < hi {
				st.retx.add(lo, hi)
				for _, a := range st.acked.spans() {
					if a.lo >= hi {
						break
					}
					st.retx.remove(a.lo, a.hi)
				}
			}
			if f.fin && !st.finAcked {
				st.finRetx = true
			}
			st.retxAvoid = avoid
			s.queueRetxLocked(st)
		case fkMaxData:
			if !s.maxDataPend {
				s.maxDataPend = true
				s.queueCtrlLocked(ctrlItem{kind: fkMaxData})
			}
		case fkMaxStreamData:
			if st != nil && !st.readClosed && !st.finKnown && !st.maxPending {
				st.maxPending = true
				s.queueCtrlLocked(ctrlItem{kind: fkMaxStreamData, sid: st.id})
			}
		case fkReset:
			if st != nil && st.resetPending && !st.resetQd {
				st.resetQd = true
				s.queueCtrlLocked(ctrlItem{kind: fkReset, sid: st.id})
			}
		case fkStop:
			if st != nil && st.readClosed && !st.recvDone() && !st.stopPending {
				st.stopPending = true
				s.queueCtrlLocked(ctrlItem{kind: fkStop, sid: st.id})
			}
		}
	}
}

// consumedLocked accounts n bytes read by the caller (read) or discarded,
// and queues window updates once half a window is used. It reports
// whether a writer should be woken.
func (s *MPSession) consumedLocked(st *mpStream, n int, read bool) bool {
	s.consumed += uint64(n)
	if read {
		s.delivered += uint64(n)
	}
	wake := false
	if s.recvMax-s.consumed < sessionWindow/2 {
		s.recvMax = s.consumed + sessionWindow
		if !s.maxDataPend {
			s.maxDataPend = true
			s.queueCtrlLocked(ctrlItem{kind: fkMaxData})
		}
		wake = true
	}
	if read && !st.finKnown && st.recvMax-st.readOff < streamWindow/2 {
		st.recvMax = st.readOff + streamWindow
		if !st.maxPending {
			st.maxPending = true
			s.queueCtrlLocked(ctrlItem{kind: fkMaxStreamData, sid: st.id})
		}
		wake = true
	}
	return wake
}

// recvExtendLocked counts stream bytes up to end against the windows. It
// reports false if the peer exceeded one.
func (s *MPSession) recvExtendLocked(st *mpStream, end uint64) bool {
	if end <= st.recvHigh {
		return true
	}
	if end > st.recvMax {
		return false
	}
	s.recvTotal += end - st.recvHigh
	st.recvHigh = end
	return s.recvTotal <= s.recvMax
}

// discardRecvLocked drops what the stream holds unread and counts it as
// consumed, so the session window is not lost to a closed stream.
func (s *MPSession) discardRecvLocked(st *mpStream) {
	if st.recvHigh > st.readOff {
		n := st.recvHigh - st.readOff
		st.readOff = st.recvHigh
		s.consumedLocked(st, int(n), false)
	}
	st.rbuf.discard()
}

// closeRecvLocked stops reading: what arrives from now on is discarded,
// and the peer is asked to stop if its direction has not ended.
func (s *MPSession) closeRecvLocked(st *mpStream) {
	if st.readClosed {
		return
	}
	st.readClosed = true
	s.discardRecvLocked(st)
	if !st.recvDone() && !st.stopPending {
		st.stopPending = true
		s.queueCtrlLocked(ctrlItem{kind: fkStop, sid: st.id})
	}
}

// resetSendLocked abandons the send side and tells the peer how many
// bytes it carried.
func (s *MPSession) resetSendLocked(st *mpStream, code uint64) {
	if st.resetOut || st.finAcked {
		return
	}
	s.dropSendLocked(st)
	st.resetOut, st.resetPending, st.resetQd, st.resetCode = true, true, true, code
	s.queueCtrlLocked(ctrlItem{kind: fkReset, sid: st.id})
}

// dropSendLocked forgets everything not yet sent and stops resending: the
// final size is what was sent so far.
func (s *MPSession) dropSendLocked(st *mpStream) {
	st.retx = rangeSet{}
	st.acked = rangeSet{}
	st.finRetx = false
	st.sbuf.Discard(st.sbuf.Len())
	st.writeOff, st.ackBase = st.sentOff, st.sentOff
	signal(st.writable)
}

// maybeFreeLocked removes a stream once both directions ended and no
// control frame for it is still queued.
func (s *MPSession) maybeFreeLocked(st *mpStream) {
	if st.freed || !st.sendDone() || !st.recvDone() || st.resetQd || st.stopPending {
		return
	}
	s.freeLocked(st)
}

func (s *MPSession) freeLocked(st *mpStream) {
	if st.freed {
		return
	}
	st.freed = true
	delete(s.streams, st.id)
	if !st.local {
		s.peerOpen--
		s.peerClosed.add(uint64(st.id), uint64(st.id)+1)
	}
	signal(st.readable)
	signal(st.writable)
}

// newSentLocked returns a sent-packet record, reusing a released one.
func (s *MPSession) newSentLocked() *sentPacket {
	if n := len(s.freeSent); n > 0 {
		sp := s.freeSent[n-1]
		s.freeSent = s.freeSent[:n-1]
		return sp
	}
	return &sentPacket{}
}

// releaseSent returns a record to the free list.
func (s *MPSession) releaseSent(sp *sentPacket) {
	frames := sp.frames[:0]
	*sp = sentPacket{frames: frames}
	if len(s.freeSent) < 4096 {
		s.freeSent = append(s.freeSent, sp)
	}
}
