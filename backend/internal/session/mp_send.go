package session

import (
	"time"

	"marmot/internal/frame"
)

// Batching: a writer builds up to maxBatch packets per lock; on a stream
// path they leave in one write. Only packets ready now are batched, so
// batching adds no delay.
const (
	maxBatch      = 4
	maxBatchBytes = 48 << 10
)

// writeLoop is the only goroutine that writes to p (the v1 invariant:
// readers never write). It sends whatever buildLocked produces and sleeps
// until a wake-up or its next timer.
func (s *MPSession) writeLoop(p *mpPath) {
	defer s.wg.Done()
	var (
		bufs   [maxBatch][]byte
		types  [maxBatch]frame.Type
		bodies [maxBatch][]byte
		wire   []byte
	)
	for i := range bufs {
		bufs[i] = make([]byte, 0, p.maxBody)
	}
	p.fbuf = make([]byte, 0, p.maxBody)
	stream, _ := p.conn.(*frame.Conn)
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		now := time.Now()
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			s.closePath(p)
			return
		}
		if p.dead {
			s.mu.Unlock()
			return
		}
		s.onTimersLocked(p, now)
		if p.draining && (p.elicitCount == 0 || now.Sub(p.drainSince) >= drainTimeout) {
			s.mu.Unlock()
			body := frame.CloseBody{Code: frame.CloseRotateComplete}.Append(nil)
			_ = p.conn.WriteRecord(frame.TypeClose, body, 0)
			s.pathFailed(p, errPathRetired)
			return
		}
		n, size := 0, 0
		for n < maxBatch && size < maxBatchBytes {
			typ, body, ok := s.buildLocked(p, now, bufs[n][:0])
			if !ok {
				break
			}
			types[n], bodies[n], bufs[n] = typ, body, body[:0]
			size += len(body)
			n++
		}
		if n > 0 {
			s.mu.Unlock()
			var err error
			if wire, err = writeBatch(p.conn, stream, wire, types[:n], bodies[:n]); err != nil {
				s.pathFailed(p, err)
				return
			}
			continue
		}
		wait := s.nextDeadlineLocked(p, now).Sub(now)
		s.mu.Unlock()
		t.Reset(max(wait, 0))
		select {
		case <-p.wake:
		case <-t.C:
		case <-p.gone:
			return
		case <-s.done:
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
	}
}

// writeBatch sends packets built by one writer pass: in a single write on
// a stream path, one datagram each otherwise. It returns wire for reuse.
func writeBatch(conn recordConn, stream *frame.Conn, wire []byte, types []frame.Type, bodies [][]byte) ([]byte, error) {
	if stream == nil {
		for i := range types {
			if err := conn.WriteRecord(types[i], bodies[i], 0); err != nil {
				return wire, err
			}
		}
		return wire, nil
	}
	wire = wire[:0]
	for i := range types {
		var err error
		if wire, err = stream.AppendRecord(wire, types[i], bodies[i], 0); err != nil {
			return wire, err
		}
	}
	return wire, stream.WriteRaw(wire)
}

// closePath ends p when the session closes: CLOSE to the peer if asked,
// then the connection.
func (s *MPSession) closePath(p *mpPath) {
	s.mu.Lock()
	notify, code, reason := s.notifyPeer && !p.dead, s.closeCode, reasonOf(s.closeErr)
	wasDead := p.dead
	p.dead = true
	s.mu.Unlock()
	if notify {
		body := frame.CloseBody{Code: code, Reason: reason}.Append(nil)
		_ = p.conn.WriteRecord(frame.TypeClose, body, 0)
	}
	_ = p.conn.Close()
	if !wasDead {
		close(p.gone)
	}
}

// onTimersLocked runs the loss and probe timers of p (spec §11.4).
func (s *MPSession) onTimersLocked(p *mpPath, now time.Time) {
	if !p.lossTime.IsZero() && !now.Before(p.lossTime) {
		s.detectLostLocked(p, now)
	}
	d, ok := p.ptoDeadline()
	if !ok || now.Before(d) {
		return
	}
	p.ptoCount++
	p.needProbe = true
	if !p.suspect {
		wasFirst := len(s.order) > 0 && s.order[0] == p
		p.suspect = true
		s.reorderLocked()
		if wasFirst {
			// The failover of v2: the leading path stopped being
			// acknowledged and its traffic moves to the next healthy path,
			// or to one the link adds now (a relay, say).
			if next := s.order[0]; next.healthy() {
				s.log.Info("failover", "from", p.meta, "via", next.meta)
			} else {
				s.log.Info("failover", "from", p.meta, "via", "none healthy yet")
			}
		}
		if cb := s.cfg.OnPathSuspect; cb != nil {
			info := p.info(wasFirst)
			go cb(info)
		}
	}
	// Whatever is in flight here may be gone: send it again elsewhere now
	// rather than after the path is declared dead (ADR-0013 §5).
	for _, sp := range p.sent {
		if sp.ackEliciting && !sp.acked && !sp.lost && !sp.requeued {
			sp.requeued = true
			s.framesLostLocked(sp.frames, p.id)
		}
	}
	s.wakeWriters()
}

// carriesLocked reports whether p may take frames other than PING and
// ACK now. A suspect path does not, while another path is healthy: what
// it would carry could be lost again (a probe packet would otherwise pick
// up the very control frames requeued from it).
func (s *MPSession) carriesLocked(p *mpPath) bool {
	if p.draining {
		return false
	}
	if p.suspect {
		return !s.otherHealthyLocked(p) && (p.hasRoom() || p.needProbe)
	}
	return p.hasRoom()
}

// nextDeadlineLocked is when p's writer must look again without a wake-up.
func (s *MPSession) nextDeadlineLocked(p *mpPath, now time.Time) time.Time {
	next := now.Add(time.Second)
	earlier := func(t time.Time) {
		if !t.IsZero() && t.Before(next) {
			next = t
		}
	}
	if p.ackPending > 0 {
		earlier(p.ackDue)
	}
	earlier(p.lossTime)
	if d, ok := p.ptoDeadline(); ok {
		earlier(d)
	}
	if p.elicitCount == 0 {
		earlier(p.lastElicit.Add(s.cfg.ProbeInterval))
	}
	if p.draining {
		earlier(p.drainSince.Add(drainTimeout))
	}
	return next
}

// buildLocked assembles the next packet for p into dst, if there is
// anything to send, and records it as sent.
func (s *MPSession) buildLocked(p *mpPath, now time.Time, dst []byte) (frame.Type, []byte, bool) {
	if len(p.repairQ) > 0 && !p.suspect {
		return s.buildRepairLocked(p, now, dst)
	}
	fecSource := p.datagram && s.fecEnc.Enabled() && p.maxBody > fecReserve+64
	limit := p.maxBody - 8
	if fecSource {
		limit = p.maxBody - fecReserve
	}

	frames := p.fbuf[:0]
	ackDue := p.ackNow || (p.ackPending > 0 && !now.Before(p.ackDue))
	withAck := p.ackStale
	if withAck {
		frames = s.appendAckLocked(frames, p, now)
	}
	sp := s.newSentLocked()
	fr := sp.frames[:0]
	if s.carriesLocked(p) {
		frames, fr = s.appendCtrlLocked(frames, fr, limit)
		frames, fr = s.appendRetxLocked(p, frames, fr, limit)
		frames, fr = s.appendDupLocked(p, frames, fr, limit, now)
		if s.eligibleNewLocked(p) {
			frames, fr = s.appendNewLocked(p, frames, fr, limit, now)
		}
	}
	eliciting := len(fr) > 0
	keepalive := p.elicitCount == 0 && !now.Before(p.lastElicit.Add(s.cfg.ProbeInterval))
	if !eliciting && (p.needProbe || keepalive) {
		frames = frame.AppendPing(frames)
		eliciting = true
	}
	if !eliciting && (!withAck || !ackDue) {
		sp.frames = fr
		s.releaseSent(sp)
		return 0, nil, false
	}
	if withAck {
		p.ackPending, p.ackNow, p.ackDue, p.ackStale = 0, false, time.Time{}, false
	}
	if eliciting {
		p.needProbe = false
	}
	pn := p.nextPN
	p.nextPN++
	typ := frame.TypePacket
	var body []byte
	if fecSource && eliciting {
		s.fecSym = frame.AppendFECSymbol(s.fecSym[:0], p.id, pn, frames)
		group, ix := s.fecEnc.Add(s.fecSym)
		body = frame.FECSource{PN: pn, Group: group, Index: ix}.Append(dst)
		typ = frame.TypePacketFEC
	} else {
		body = frame.AppendPacketHeader(dst, pn)
	}
	body = append(body, frames...)
	p.fbuf = frames[:0]

	sp.pn, sp.at, sp.size, sp.ackEliciting, sp.frames = pn, now, len(body), eliciting, fr
	sp.delivered, sp.deliveredAt = p.delivered, p.deliveredAt
	p.track(sp)
	if typ == frame.TypePacketFEC {
		s.afterFECSourceLocked(p)
	}
	return typ, body, true
}

// appendAckLocked appends an ACK for the packets received on p.
func (s *MPSession) appendAckLocked(b []byte, p *mpPath, now time.Time) []byte {
	spans := p.recvd.spans()
	var ranges [frame.MaxAckRanges]frame.AckRange
	n := 0
	for i := len(spans) - 1; i >= 0 && n < len(ranges); i-- {
		ranges[n] = frame.AckRange{Lo: spans[i].lo, Hi: spans[i].hi - 1}
		n++
	}
	if n == 0 {
		return b
	}
	delay := now.Sub(p.largestAt)
	return frame.AppendAck(b, uint64(max(delay, 0)/time.Microsecond), ranges[:n])
}

// ctrlSize bounds the encoding of any control frame.
const ctrlSize = 1 + 10 + 10

// appendCtrlLocked appends owed control frames that still apply.
func (s *MPSession) appendCtrlLocked(b []byte, fr []sentFrame, limit int) ([]byte, []sentFrame) {
	kept := s.ctrlQ[:0]
	for i, it := range s.ctrlQ {
		if len(b)+ctrlSize > limit {
			kept = append(kept, s.ctrlQ[i:]...)
			break
		}
		st := s.streams[it.sid]
		switch it.kind {
		case fkMaxData:
			b = frame.AppendMaxData(b, s.recvMax)
			s.maxDataPend = false
		case fkMaxStreamData:
			if st == nil || !st.maxPending {
				continue
			}
			b = frame.AppendMaxStreamData(b, st.id, st.recvMax)
			st.maxPending = false
		case fkStop:
			if st == nil || !st.stopPending {
				continue
			}
			b = frame.AppendStop(b, st.id)
			st.stopPending = false
		case fkReset:
			if st == nil || !st.resetQd {
				continue
			}
			b = frame.AppendReset(b, st.id, st.resetCode, st.sentOff)
			st.resetQd = false
		}
		fr = append(fr, sentFrame{kind: it.kind, sid: it.sid})
		if st != nil {
			s.maybeFreeLocked(st)
		}
	}
	s.ctrlQ = kept
	return b, fr
}
