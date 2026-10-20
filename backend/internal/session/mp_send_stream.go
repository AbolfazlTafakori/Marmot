package session

import (
	"net"
	"time"

	"marmot/internal/frame"
)

// minStreamFrame is the least room worth starting a STREAM frame in.
const minStreamFrame = 32

// appendRetxLocked appends lost stream bytes. A path skips bytes lost on
// itself while another path is healthy: they go elsewhere first.
func (s *MPSession) appendRetxLocked(p *mpPath, b []byte, fr []sentFrame, limit int) ([]byte, []sentFrame) {
	if len(s.retxQ) == 0 {
		return b, fr
	}
	other := s.otherHealthyLocked(p)
	kept := s.retxQ[:0]
	for _, st := range s.retxQ {
		if st.freed || !st.hasRetx() {
			st.retxQd = false
			continue
		}
		if (st.retxAvoid == p.id && other) || limit-len(b) < minStreamFrame {
			kept = append(kept, st)
			continue
		}
		b, fr = s.appendStreamRetx(st, b, fr, limit)
		if st.hasRetx() {
			kept = append(kept, st)
		} else {
			st.retxQd = false
		}
	}
	clear(s.retxQ[len(kept):])
	s.retxQ = kept
	return b, fr
}

func (s *MPSession) appendStreamRetx(st *mpStream, b []byte, fr []sentFrame, limit int) ([]byte, []sentFrame) {
	for {
		sp, ok := st.retx.first()
		if !ok {
			break
		}
		room := limit - len(b) - frame.StreamOverhead(st.id, sp.lo, int(sp.hi-sp.lo))
		if room <= 0 {
			return b, fr
		}
		n := min(int(sp.hi-sp.lo), room)
		end := sp.lo + uint64(n)
		fin := st.finWanted && st.finSent && end == st.writeOff && !st.finAcked
		b = frame.AppendStreamHeader(b, st.id, sp.lo, fin, n)
		b = st.sbuf.AppendRange(b, int(sp.lo-st.ackBase), n)
		st.retx.remove(sp.lo, end)
		if fin {
			st.finRetx = false
		}
		fr = append(fr, sentFrame{kind: fkStream, sid: st.id, off: sp.lo, n: n, fin: fin})
	}
	if st.finRetx && limit-len(b) >= frame.StreamOverhead(st.id, st.writeOff, 0) {
		b = frame.AppendStreamHeader(b, st.id, st.writeOff, true, 0)
		fr = append(fr, sentFrame{kind: fkStream, sid: st.id, off: st.writeOff, fin: true})
		st.finRetx = false
	}
	return b, fr
}

// appendNewLocked appends bytes never sent: VIP streams first, then the
// rest round-robin, within the stream and session windows.
func (s *MPSession) appendNewLocked(p *mpPath, b []byte, fr []sentFrame, limit int, now time.Time) ([]byte, []sentFrame) {
	for _, qp := range [...]*[]*mpStream{&s.vipQ, &s.sendQ} {
		q := *qp
		for len(q) > 0 {
			st := q[0]
			if st.freed || !st.canSendNew() {
				st.queued = false
				q[0] = nil
				q = q[1:]
				continue
			}
			avail := min(st.writeOff, st.sendMax) - st.sentOff
			n := int(min(avail, s.sendMax-s.sentNew))
			finOnly := st.finWanted && !st.finSent && st.sentOff == st.writeOff
			if n == 0 && !finOnly {
				break // the session window is exhausted
			}
			room := limit - len(b) - frame.StreamOverhead(st.id, st.sentOff, n)
			if room < 0 || (room == 0 && n > 0) {
				break // the packet is full
			}
			n = min(n, room)
			off := st.sentOff
			fin := st.finWanted && !st.finSent && off+uint64(n) == st.writeOff
			b = frame.AppendStreamHeader(b, st.id, off, fin, n)
			b = st.sbuf.AppendRange(b, int(off-st.ackBase), n)
			st.sentOff += uint64(n)
			s.sentNew += uint64(n)
			if fin {
				st.finSent = true
			}
			fr = append(fr, sentFrame{kind: fkStream, sid: st.id, off: off, n: n, fin: fin})
			if st.vip && len(s.dupQ) < maxDupQueue {
				s.dupQ = append(s.dupQ, dupItem{sid: st.id, off: off, n: n, fin: fin, origin: p.id, at: now})
				if t := s.dupTargetLocked(p.id); t != nil {
					signal(t.wake)
				}
			}
			q[0] = nil
			q = q[1:]
			st.queued = false
			if st.canSendNew() { // to the back: round-robin
				st.queued = true
				q = append(q, st)
			}
		}
		*qp = q
	}
	return b, fr
}

// appendDupLocked sends VIP ranges again on p if p is the path chosen to
// duplicate them: the best other path, on a different peer address when
// there is one.
func (s *MPSession) appendDupLocked(p *mpPath, b []byte, fr []sentFrame, limit int, now time.Time) ([]byte, []sentFrame) {
	if len(s.dupQ) == 0 {
		return b, fr
	}
	kept := s.dupQ[:0]
	for _, d := range s.dupQ {
		st := s.streams[d.sid]
		if st == nil || st.sendAborted() || now.Sub(d.at) > dupMaxAge {
			continue
		}
		end := d.off + uint64(d.n)
		off, n := max(d.off, st.ackBase), 0
		if off < end {
			n = int(end - off)
		} else {
			off = end
		}
		if n == 0 && (!d.fin || st.finAcked) {
			continue // already acknowledged
		}
		target := s.dupTargetLocked(d.origin)
		if target == nil {
			continue
		}
		if target != p || limit-len(b) < frame.StreamOverhead(st.id, off, n)+n {
			kept = append(kept, d)
			continue
		}
		b = frame.AppendStreamHeader(b, st.id, off, d.fin, n)
		b = st.sbuf.AppendRange(b, int(off-st.ackBase), n)
		fr = append(fr, sentFrame{kind: fkStream, sid: st.id, off: off, n: n, fin: d.fin})
	}
	s.dupQ = kept
	return b, fr
}

// dupTargetLocked picks the path that duplicates what origin sent.
func (s *MPSession) dupTargetLocked(origin uint64) *mpPath {
	o := s.paths[origin]
	var fallback *mpPath
	for _, q := range s.order {
		if q.id == origin || !q.healthy() {
			continue
		}
		if o == nil || hostOf(q.meta.Remote) != hostOf(o.meta.Remote) {
			return q
		}
		if fallback == nil {
			fallback = q
		}
	}
	return fallback
}

// hostOf strips the port from a "host:port" remote; other forms (a relayed
// path's "via id") are returned whole.
func hostOf(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}
