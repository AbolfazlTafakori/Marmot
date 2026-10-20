package session

import (
	"errors"
	"time"

	"marmot/internal/fec"
	"marmot/internal/frame"
)

// errSessionProtocol marks a violation that ends the whole session (spec
// §11.3), as opposed to one that ends only the path it arrived on.
var errSessionProtocol = errors.New("session: protocol violation")

// readLoop reads and handles p's records until p fails. It never writes
// to p: replies are left for p's writer.
func (s *MPSession) readLoop(p *mpPath) {
	defer s.wg.Done()
	for {
		typ, body, err := p.conn.ReadRecord()
		if err != nil {
			s.pathFailed(p, err)
			return
		}
		if err := s.onRecord(p, typ, body); err != nil {
			switch {
			case errors.Is(err, errSessionProtocol):
				s.log.Warn("protocol violation; closing session", "via", p.meta, "err", err)
				s.shutdown(errProtocol, frame.CloseProtocolError, true)
			case errors.Is(err, errProtocol):
				s.log.Warn("protocol violation on path", "via", p.meta, "type", typ, "err", err)
			}
			s.pathFailed(p, err)
			return
		}
	}
}

func (s *MPSession) onRecord(p *mpPath, typ frame.Type, body []byte) error {
	now := time.Now()
	switch typ {
	case frame.TypePacket:
		pn, frames, err := frame.ParsePacket(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.received(p, len(body), now)
		fresh, err := s.onPacketLocked(p, pn, frames, now)
		if fresh {
			p.pktsRecv++
		}
		return err
	case frame.TypePacketFEC:
		h, frames, err := frame.ParseFECSource(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.received(p, len(body), now)
		fresh, err := s.onPacketLocked(p, h.PN, frames, now)
		if err != nil || !fresh {
			return err
		}
		p.pktsRecv++
		s.fecSym = frame.AppendFECSymbol(s.fecSym[:0], p.id, h.PN, frames)
		return s.recoveredLocked(s.fecDec.AddSource(h.Group, h.Index, s.fecSym), now)
	case frame.TypeRepair:
		h, parity, err := frame.ParseFECRepair(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.received(p, len(body), now)
		if !s.markRecvLocked(p, h.PN, false, now) {
			return nil
		}
		p.pktsRecv++
		return s.recoveredLocked(s.fecDec.AddParity(h.Group, h.K, h.M, h.Index, parity), now)
	case frame.TypeClose:
		cb, err := frame.ParseClose(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		if cb.Code == frame.CloseRotateComplete {
			return errPathRetired
		}
		s.log.Info("session closed by peer", "code", cb.Code, "reason", cb.Reason)
		s.shutdown(ErrClosedByPeer, frame.CloseNormal, false)
		return ErrClosedByPeer
	default:
		return errors.Join(errProtocol, frame.ErrUnknownType)
	}
}

func (s *MPSession) received(p *mpPath, n int, now time.Time) {
	p.lastRecv = now
	p.bytesRecv += uint64(n)
}

// onPacketLocked applies the frames of packet pn of p unless it is a
// duplicate. It reports whether the packet was new.
func (s *MPSession) onPacketLocked(p *mpPath, pn uint64, frames []byte, now time.Time) (bool, error) {
	if pn < p.recvFloor || p.recvd.contains(pn) {
		return false, nil
	}
	eliciting := false
	f := &s.rframe
	for rest := frames; len(rest) > 0; {
		var err error
		if rest, err = frame.ParseFrame(rest, f); err != nil {
			return false, errors.Join(errSessionProtocol, err)
		}
		if f.Type != frame.FrameAck {
			eliciting = true
		}
		if err := s.applyFrameLocked(p, f, now); err != nil {
			return false, err
		}
	}
	s.markRecvLocked(p, pn, eliciting, now)
	return true, nil
}

// markRecvLocked records packet pn of p as received and schedules its
// acknowledgement (spec §11.4). It reports false for a duplicate.
func (s *MPSession) markRecvLocked(p *mpPath, pn uint64, eliciting bool, now time.Time) bool {
	if pn < p.recvFloor || p.recvd.contains(pn) {
		return false
	}
	p.recvd.add(pn, pn+1)
	if floor := p.recvd.limit(maxRecvRanges); floor > p.recvFloor {
		p.recvFloor = floor
	}
	switch {
	case !p.anyRecv || pn > p.largestRecv:
		if p.anyRecv && pn > p.largestRecv+1 && eliciting {
			p.ackNow = true // a gap: tell the sender at once
		}
		p.largestRecv, p.largestAt, p.anyRecv = pn, now, true
	case eliciting:
		p.ackNow = true // out of order
	}
	p.ackStale = true
	if eliciting {
		p.ackPending++
		every := ackEveryStream
		if p.datagram {
			every = ackEveryDatagram
		}
		if p.ackPending >= every {
			p.ackNow = true
		}
		if p.ackDue.IsZero() {
			p.ackDue = now.Add(maxAckDelay)
		}
		signal(p.wake)
	}
	return true
}

// recoveredLocked processes packets FEC rebuilt, each as if it had
// arrived on its own path (ADR-0014 §4).
func (s *MPSession) recoveredLocked(recs []fec.Recovered, now time.Time) error {
	for _, r := range recs {
		id, pn, frames, err := frame.ParseFECSymbol(r.Symbol)
		if err != nil {
			continue
		}
		q := s.paths[id]
		if q == nil || q.dead {
			continue // its frames are resent anyway
		}
		fresh, err := s.onPacketLocked(q, pn, frames, now)
		if err != nil {
			return err
		}
		if fresh {
			q.recovered++
		}
	}
	return nil
}

// applyFrameLocked handles one frame received on p.
func (s *MPSession) applyFrameLocked(p *mpPath, f *frame.Frame, now time.Time) error {
	switch f.Type {
	case frame.FramePing:
	case frame.FrameAck:
		return s.onAckLocked(p, f, now)
	case frame.FrameStream:
		return s.onStreamLocked(f)
	case frame.FrameReset:
		return s.onResetLocked(f)
	case frame.FrameStop:
		if st := s.streams[f.StreamID]; st != nil && !st.stopped {
			st.stopped = true
			s.resetSendLocked(st, 0)
			s.maybeFreeLocked(st)
			signal(st.writable)
			s.wakeWriters()
		}
	case frame.FrameMaxStreamData:
		if st := s.streams[f.StreamID]; st != nil && f.Max > st.sendMax {
			st.sendMax = f.Max
			s.queueSendLocked(st)
			s.wakeWriters()
		}
	case frame.FrameMaxData:
		if f.Max > s.sendMax {
			s.sendMax = f.Max
			for _, st := range s.streams {
				s.queueSendLocked(st)
			}
			s.wakeWriters()
		}
	}
	return nil
}

// streamForLocked finds the stream a frame refers to, opening it if the
// peer starts a new one. It returns nil for a stream already gone.
func (s *MPSession) streamForLocked(id uint32) (*mpStream, error) {
	if st := s.streams[id]; st != nil {
		return st, nil
	}
	if id == 0 {
		return nil, errors.Join(errSessionProtocol, errors.New("stream id 0"))
	}
	if own := (id%2 == 1) == (s.role == Initiator); own {
		if id >= s.nextID {
			return nil, errors.Join(errSessionProtocol, errors.New("stream we never opened"))
		}
		return nil, nil
	}
	if s.peerClosed.contains(uint64(id)) || s.closed {
		return nil, nil
	}
	st := newMPStream(s, id, false)
	s.streams[id] = st
	s.peerOpen++
	if s.peerOpen > maxPeerStreams {
		s.refuseLocked(st)
		return st, nil
	}
	select {
	case s.acceptQ <- st:
	default:
		s.refuseLocked(st)
	}
	return st, nil
}

// refuseLocked aborts a stream the peer opened that cannot be accepted.
func (s *MPSession) refuseLocked(st *mpStream) {
	s.resetSendLocked(st, 0)
	s.closeRecvLocked(st)
	st.closedAt = time.Now()
}

// onStreamLocked handles a STREAM frame.
func (s *MPSession) onStreamLocked(f *frame.Frame) error {
	st, err := s.streamForLocked(f.StreamID)
	if st == nil || err != nil {
		return err
	}
	end := f.Offset + uint64(len(f.Data))
	if (st.finKnown && end > st.finOff) || (f.Fin && ((st.finKnown && end != st.finOff) || end < st.recvHigh)) {
		return errors.Join(errSessionProtocol, errors.New("stream final size changed"))
	}
	if !s.recvExtendLocked(st, end) {
		return errors.Join(errSessionProtocol, errors.New("flow control limit exceeded"))
	}
	if f.Fin {
		st.finKnown, st.finOff = true, end
	}
	switch {
	case st.resetIn:
		return nil
	case st.readClosed:
		s.discardRecvLocked(st)
	case end > st.readOff:
		off, data := f.Offset, f.Data
		if off < st.readOff {
			data = data[st.readOff-off:]
			off = st.readOff
		}
		st.rbuf.write(st.readOff, off, data)
	}
	if st.rbuf.contiguous(st.readOff) > 0 || st.recvDone() {
		signal(st.readable)
	}
	s.maybeFreeLocked(st)
	return nil
}

// onResetLocked handles RESET: the peer abandoned its direction after
// Final bytes, which still count against the windows.
func (s *MPSession) onResetLocked(f *frame.Frame) error {
	st, err := s.streamForLocked(f.StreamID)
	if st == nil || err != nil || st.resetIn {
		return err
	}
	if f.Final < st.recvHigh || (st.finKnown && f.Final != st.finOff) {
		return errors.Join(errSessionProtocol, errors.New("reset below received data"))
	}
	if !s.recvExtendLocked(st, f.Final) {
		return errors.Join(errSessionProtocol, errors.New("flow control limit exceeded"))
	}
	st.resetIn, st.finKnown, st.finOff = true, true, f.Final
	s.discardRecvLocked(st)
	st.stopPending = false
	signal(st.readable)
	s.maybeFreeLocked(st)
	return nil
}
