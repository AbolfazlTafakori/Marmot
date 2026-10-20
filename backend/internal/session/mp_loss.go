package session

import (
	"errors"
	"sort"
	"time"

	"marmot/internal/frame"
)

// packetThreshold is how many later packets must be acknowledged before an
// earlier one counts as lost (RFC 9002 §6.1.1).
const packetThreshold = 3

// onAckLocked handles an ACK received on p for p's own packets.
func (s *MPSession) onAckLocked(p *mpPath, f *frame.Frame, now time.Time) error {
	if len(f.Ranges) == 0 {
		return nil
	}
	largest := f.Ranges[0].Hi
	if largest >= p.nextPN {
		return errors.Join(errSessionProtocol, errors.New("ack of a packet never sent"))
	}
	var largestNew *sentPacket
	newly := false
	for _, r := range f.Ranges {
		i := sort.Search(len(p.sent), func(i int) bool { return p.sent[i].pn >= r.Lo })
		for ; i < len(p.sent) && p.sent[i].pn <= r.Hi; i++ {
			sp := p.sent[i]
			if sp.acked {
				continue
			}
			if !sp.lost {
				p.settle(sp)
				p.onDelivered(sp, now)
			}
			sp.acked = true
			newly = true
			s.framesAckedLocked(sp.frames)
			if sp.pn == largest {
				largestNew = sp
			}
		}
	}
	if !newly {
		return nil
	}
	if !p.anyAcked || largest > p.largestAcked {
		p.largestAcked, p.anyAcked = largest, true
	}
	if largestNew != nil && largestNew.ackEliciting {
		p.observeRTT(now.Sub(largestNew.at), time.Duration(f.DelayUs)*time.Microsecond)
	}
	p.ptoCount = 0
	p.lastProgress = now
	if p.suspect {
		p.suspect = false
		s.reorderLocked()
		s.wakeWriters()
	}
	s.detectLostLocked(p, now)
	signal(p.wake)
	return nil
}

// detectLostLocked declares lost the packets of p that later
// acknowledgements show missing, and sets the time-threshold timer for the
// rest.
func (s *MPSession) detectLostLocked(p *mpPath, now time.Time) {
	p.lossTime = time.Time{}
	if !p.anyAcked {
		p.pruneSent(s.releaseSent)
		return
	}
	delay := p.lossDelay()
	requeued := false
	for _, sp := range p.sent {
		if sp.pn > p.largestAcked {
			break
		}
		if sp.acked || sp.lost {
			continue
		}
		if p.largestAcked-sp.pn < packetThreshold && now.Sub(sp.at) < delay {
			if t := sp.at.Add(delay); p.lossTime.IsZero() || t.Before(p.lossTime) {
				p.lossTime = t
			}
			continue
		}
		sp.lost = true
		p.settle(sp)
		p.pktsLost++
		if !sp.requeued && len(sp.frames) > 0 {
			s.framesLostLocked(sp.frames, p.id)
			requeued = true
		}
		if sp.ackEliciting {
			p.onCongestion(sp.pn, now)
		}
	}
	p.pruneSent(s.releaseSent)
	if requeued {
		s.wakeWriters()
	}
}
