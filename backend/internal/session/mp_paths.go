package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/transport"
)

// pathID names a path by its handshake hash (spec §11.1).
func pathID(keys crypto.CipherPair) uint64 { return binary.BigEndian.Uint64(keys.Binding[:8]) }

// addPath attaches a handshaken path and starts its reader and writer.
// The session owns conn from here on, including on error.
func (s *MPSession) addPath(conn transport.Conn, keys crypto.CipherPair, meta PathMeta) (*mpPath, error) {
	rc, datagram, maxBody := newPathConn(conn, keys)
	id := pathID(keys)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = rc.Close()
		return nil, ErrClosed
	}
	if s.paths[id] != nil {
		s.mu.Unlock()
		_ = rc.Close()
		return nil, errDuplicatePath
	}
	p := newMPPath(id, meta, rc, datagram, maxBody, time.Now())
	if _, unpaced := conn.(transport.Unpaced); unpaced && datagram {
		p.pace, p.tokens, p.paceAt = true, float64(paceBurst*maxBody), time.Now()
	}
	p.needProbe = true // measure RTT at once
	s.paths[id] = p
	if s.resumeTimer != nil {
		s.resumeTimer.Stop()
		s.resumeTimer = nil
	}
	s.reorderLocked()
	s.mu.Unlock()

	s.log.Debug("path added", "path", fmt.Sprintf("%016x", id), "via", meta, "datagram", datagram)
	s.wg.Add(2)
	go s.readLoop(p)
	go s.writeLoop(p)
	return p, nil
}

// addInbound implements acceptedSession.
func (s *MPSession) addInbound(conn transport.Conn, keys crypto.CipherPair, meta PathMeta) error {
	_, err := s.addPath(conn, keys, meta)
	return err
}

// Join implements PeerSession. With rotate, the first-ranked path drains
// once the new path is up (ADR-0013 §10).
func (s *MPSession) Join(ctx context.Context, conn transport.Conn, meta PathMeta, rotate bool) error {
	if s.role != Initiator {
		_ = conn.Close()
		return ErrNotInitiator
	}
	flags := crypto.FlagJoin
	if rotate {
		flags |= crypto.FlagRotate
	}
	hello := crypto.Hello{Flags: flags, SessionID: s.id, NodeID: s.localID, Caps: s.caps}
	keys, _, err := clientHandshake(ctx, conn, s.local, s.peerKey, hello)
	if err != nil {
		return fmt.Errorf("join %s: %w", meta, err)
	}
	p, err := s.addPath(conn, keys, meta)
	if err != nil {
		return err
	}
	if rotate {
		s.mu.Lock()
		for _, q := range s.order {
			if q != p && !q.draining && !q.dead {
				q.draining, q.drainSince = true, time.Now()
				s.reorderLocked()
				signal(q.wake)
				break
			}
		}
		s.mu.Unlock()
	}
	return nil
}

// reorderLocked recomputes the scheduling order of the paths.
func (s *MPSession) reorderLocked() {
	s.order = s.order[:0]
	for _, p := range s.paths {
		s.order = append(s.order, p)
	}
	slices.SortFunc(s.order, pathLess(s.ranks))
	for i, p := range s.order {
		p.order = i
	}
	list := slices.Clone(s.order)
	s.wakeList.Store(&list)
}

// wakeWriters wakes every path writer. It does not block and may be
// called with or without the lock.
func (s *MPSession) wakeWriters() {
	for _, p := range *s.wakeList.Load() {
		signal(p.wake)
	}
}

// bestSuspectLocked is the path to carry data when none is healthy: a
// suspect path that has received something since it turned suspect (its
// peer still reaches it) before one that has not, then the one that
// received most recently. Rank or the last acknowledgement would pick a
// busy path that just died over an idle one that is alive. It is nil while
// some path is healthy.
func (s *MPSession) bestSuspectLocked() *mpPath {
	var best *mpPath
	alive := func(q *mpPath) bool { return q.lastRecv.After(q.suspectAt) }
	for _, q := range s.order {
		if q.healthy() {
			return nil
		}
		if !q.suspect || q.draining || q.dead {
			continue
		}
		switch {
		case best == nil:
			best = q
		case alive(q) != alive(best):
			if alive(q) {
				best = q
			}
		case q.lastRecv.After(best.lastRecv):
			best = q
		}
	}
	return best
}

// healthyDirectLocked reports whether a direct path can take data.
func (s *MPSession) healthyDirectLocked() bool {
	for _, p := range s.order {
		if p.healthy() && !p.relayed {
			return true
		}
	}
	return false
}

// usableLocked reports whether p may carry new data under the relay rule:
// relayed paths only while no direct path is healthy.
func (s *MPSession) usableLocked(p *mpPath, direct bool) bool {
	return p.healthy() && (!p.relayed || !direct)
}

// eligibleNewLocked reports whether p should take new stream data now:
// it is usable and every better path is full (min-RTT scheduling).
func (s *MPSession) eligibleNewLocked(p *mpPath) bool {
	direct := s.healthyDirectLocked()
	if !s.usableLocked(p, direct) {
		// With no healthy path at all, the suspect one acknowledged most
		// recently keeps carrying: on a lossy path suspicion comes and
		// goes, and waiting out each probe would stall every stream.
		return p == s.bestSuspectLocked()
	}
	for _, q := range s.order {
		if q == p {
			return true
		}
		if s.usableLocked(q, direct) && q.hasRoom() {
			return false
		}
	}
	return true
}

// otherHealthyLocked reports whether a path other than p is healthy.
func (s *MPSession) otherHealthyLocked(p *mpPath) bool {
	for _, q := range s.order {
		if q != p && q.healthy() {
			return true
		}
	}
	return false
}

// pathFailed removes p: its unacknowledged frames go to other paths. If no
// path is left, the resume timer starts.
func (s *MPSession) pathFailed(p *mpPath, cause error) {
	s.mu.Lock()
	if p.dead {
		s.mu.Unlock()
		return
	}
	p.dead = true
	wasFirst := len(s.order) > 0 && s.order[0] == p
	delete(s.paths, p.id)
	for _, sp := range p.sent {
		if sp.acked || sp.lost {
			continue
		}
		if !sp.requeued {
			s.framesLostLocked(sp.frames, 0)
		}
		p.settle(sp)
		sp.lost = true
	}
	p.pruneSent(s.releaseSent)
	p.repairQ = nil
	s.reorderLocked()
	if len(s.paths) == 0 {
		s.armResumeLocked()
	}
	// A suspect path already logged its failover when it turned suspect.
	var next *PathMeta
	if wasFirst && !p.suspect && len(s.order) > 0 && s.order[0].healthy() {
		next = &s.order[0].meta
	}
	closed := s.closed
	info := p.info(wasFirst)
	s.mu.Unlock()
	close(p.gone)
	_ = p.conn.Close()
	s.wakeWriters()
	if closed {
		return
	}
	if errors.Is(cause, errPathRetired) {
		s.log.Debug("path retired", "via", p.meta)
	} else {
		s.log.Info("path down", "via", p.meta, "active", wasFirst, "err", cause)
		if next != nil {
			// As in v1: the path that carried most traffic is gone and the
			// next one leads now.
			s.log.Info("failover", "via", *next)
		}
	}
	if s.cfg.OnPathDown != nil {
		s.cfg.OnPathDown(info, cause)
	}
}

func (s *MPSession) armResumeLocked() {
	if s.resumeTimer != nil || s.closed {
		return
	}
	s.resumeTimer = time.AfterFunc(s.cfg.ResumeTimeout, func() {
		s.mu.Lock()
		expired := len(s.paths) == 0
		s.resumeTimer = nil
		s.mu.Unlock()
		if expired {
			s.log.Warn("session resume timeout", "timeout", s.cfg.ResumeTimeout)
			s.shutdown(ErrResumeTimeout, frame.CloseNormal, false)
		}
	})
}
