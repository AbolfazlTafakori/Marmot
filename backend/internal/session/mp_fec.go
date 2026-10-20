package session

import (
	"time"

	"marmot/internal/frame"
)

// fecReserve is the room a FEC source packet leaves so that its symbol
// fits a REPAIR record on a path of the same size (spec §11.5).
const fecReserve = frame.FECRepairHeader + frame.FECSymbolHeader

// maxFECDelay bounds how long a group waits for more sources.
const maxFECDelay = 10 * time.Millisecond

// afterFECSourceLocked closes the group when it is full, or arms the
// timer that closes a partial one (ADR-0014 §4).
func (s *MPSession) afterFECSourceLocked(p *mpPath) {
	if s.fecEnc.Full() {
		s.flushFECLocked()
		return
	}
	if s.fecArmed {
		return
	}
	s.fecArmed = true
	d := max(min(maxFECDelay, p.rtt()/4), time.Millisecond)
	if s.fecTimer == nil {
		s.fecTimer = time.AfterFunc(d, s.fecTimeout)
	} else {
		s.fecTimer.Reset(d)
	}
}

func (s *MPSession) fecTimeout() {
	s.mu.Lock()
	if s.fecArmed && !s.closed {
		s.flushFECLocked()
	}
	s.mu.Unlock()
}

// flushFECLocked closes the open group and hands its parity symbols to the
// session's datagram paths in turn, so a group survives losing a path.
func (s *MPSession) flushFECLocked() {
	if s.fecArmed && s.fecTimer != nil {
		s.fecTimer.Stop()
	}
	s.fecArmed = false
	group, k, parity, ok, err := s.fecEnc.Flush()
	if err != nil {
		s.log.Warn("fec encode failed", "err", err)
		return
	}
	if !ok {
		return
	}
	// Healthy datagram paths only: a suspect path sends no REPAIR, so a
	// parity symbol queued there would be lost with its group's chance.
	var dg []*mpPath
	for _, q := range s.order {
		if q.datagram && q.healthy() {
			dg = append(dg, q)
		}
	}
	if len(dg) == 0 {
		return
	}
	for i, par := range parity {
		q := dg[(s.fecNext+i)%len(dg)]
		if frame.FECRepairHeader+len(par) > q.maxBody {
			continue
		}
		if len(q.repairQ) >= maxRepairQueue {
			q.repairQ = q.repairQ[1:]
		}
		q.repairQ = append(q.repairQ, repairItem{group: group, k: uint8(k), m: uint8(len(parity)), ix: uint8(k + i), parity: par})
		signal(q.wake)
	}
	s.fecNext++
}

// buildRepairLocked sends the next parity symbol queued for p. REPAIR
// packets are numbered and acknowledged but never resent.
func (s *MPSession) buildRepairLocked(p *mpPath, now time.Time, dst []byte) (frame.Type, []byte, bool) {
	it := p.repairQ[0]
	p.repairQ[0] = repairItem{}
	p.repairQ = p.repairQ[1:]
	pn := p.nextPN
	p.nextPN++
	body := frame.FECRepair{PN: pn, Group: it.group, K: it.k, M: it.m, Index: it.ix}.Append(dst)
	body = append(body, it.parity...)
	sp := s.newSentLocked()
	sp.pn, sp.at, sp.size = pn, now, len(body)
	sp.delivered, sp.deliveredAt = p.delivered, p.deliveredAt
	p.track(sp)
	return frame.TypeRepair, body, true
}
