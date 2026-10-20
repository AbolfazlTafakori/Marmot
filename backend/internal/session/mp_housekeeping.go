package session

import (
	"time"
)

// timerTick is how often housekeeping runs the loss and probe timers of
// every path. A path's writer runs them too, but it may sit in a write
// that a blackholed TCP path never completes.
const timerTick = 10 * time.Millisecond

// housekeeping runs path timers, drops paths that stopped making
// progress, samples loss, re-ranks paths and frees streams whose peer went
// quiet. It does no I/O, so a path whose writes hang is still noticed.
func (s *MPSession) housekeeping() {
	defer s.wg.Done()
	t := time.NewTicker(timerTick)
	defer t.Stop()
	lastSample := time.Now()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		now := time.Now()
		s.mu.Lock()
		var dead []*mpPath
		for _, p := range s.paths {
			s.onTimersLocked(p, now)
			if s.stalledLocked(p, now) {
				dead = append(dead, p)
			}
		}
		if now.Sub(lastSample) >= time.Second {
			lastSample = now
			for _, p := range s.paths {
				p.sampleLoss()
			}
			s.reorderLocked()
			s.sweepStreamsLocked(now)
		}
		s.mu.Unlock()
		for _, p := range dead {
			s.pathFailed(p, errPathTimeout)
		}
	}
}

// stalledLocked reports whether p made no progress for DeadAfter: nothing
// received, or data outstanding and nothing acknowledged.
func (s *MPSession) stalledLocked(p *mpPath, now time.Time) bool {
	if now.Sub(p.lastRecv) > s.cfg.DeadAfter {
		return true
	}
	return p.elicitCount > 0 && now.Sub(p.progressBase()) > s.cfg.DeadAfter
}

// sweepStreamsLocked frees streams closed locally long ago whose peer
// never ended its direction; a well-behaved peer always does.
func (s *MPSession) sweepStreamsLocked(now time.Time) {
	for _, st := range s.streams {
		if !st.closedAt.IsZero() && now.Sub(st.closedAt) > streamLinger {
			s.freeLocked(st)
		}
	}
}
