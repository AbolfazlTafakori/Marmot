package session

import (
	"errors"
	"math/rand/v2"
	"time"

	"marmot/internal/frame"
)

// AddPath attaches a handshaken path. On the initiator the first path
// becomes active at once; later ones are hot standbys. The conn owns conn
// from here on, including on error.
func (c *ResumableConn) AddPath(conn *frame.Conn, meta PathMeta) (uint64, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return 0, ErrClosed
	}
	c.nextID++
	p := newPath(c.nextID, meta, conn, time.Now())
	c.paths[p.id] = p
	activate := c.cfg.Role == Initiator && c.active == nil
	c.mu.Unlock()

	c.log.Debug("path added", "path", p.id, "via", meta)
	c.wg.Add(2)
	go c.readLoop(p)
	go c.controlLoop(p)
	if activate {
		c.activate(p)
	}
	return p.id, nil
}

// Promote makes path id the active one. With retireOld the previous active
// path is closed as soon as the new one is ready (make-before-break
// rotation); otherwise it stays as a standby.
func (c *ResumableConn) Promote(id uint64, retireOld bool) error {
	if c.cfg.Role != Initiator {
		return ErrNotInitiator
	}
	c.mu.Lock()
	p, ok := c.paths[id]
	if !ok {
		c.mu.Unlock()
		return ErrUnknownPath
	}
	if retireOld && c.active != nil && c.active != p {
		c.retiring = c.active
	}
	c.mu.Unlock()
	c.activate(p)
	return nil
}

// activate tells the peer that p is now active, from the initiator.
// Sending pauses until the peer answers with its own resume offset.
func (c *ResumableConn) activate(p *path) {
	c.mu.Lock()
	if c.closed || p.dead.Load() {
		c.mu.Unlock()
		return
	}
	c.epoch++
	c.active, c.ready = p, false
	c.gen++
	body := frame.Activate{Offset: c.recvOff, Epoch: c.epoch}.Append(nil)
	c.armResumeLocked()
	c.mu.Unlock()

	c.control(p, func() error { return p.conn.WriteRecord(frame.TypeActivate, body, 0) })
}

// onActivate handles an ACTIVATE record received on p.
func (c *ResumableConn) onActivate(p *path, a frame.Activate) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if a.Offset > c.writeOff {
		c.mu.Unlock()
		c.shutdown(errProtocol, frame.CloseProtocolError, true)
		return
	}
	resendFrom := max(a.Offset, c.ackedOff)

	if c.cfg.Role == Initiator {
		// The answer to our own ACTIVATE; anything else is stale.
		if a.Epoch != c.epoch || c.active != p || c.ready {
			c.mu.Unlock()
			return
		}
		c.sentOff, c.ready = resendFrom, true
		c.disarmResumeLocked()
		old := c.retiring
		c.retiring = nil
		c.mu.Unlock()
		c.kick()
		if old != nil && old != p {
			c.retire(old)
		}
		return
	}

	if a.Epoch <= c.epoch {
		c.mu.Unlock()
		return
	}
	c.epoch, c.active, c.ready = a.Epoch, p, false
	c.gen++
	gen := c.gen
	c.sentOff = resendFrom
	reply := frame.Activate{Offset: c.recvOff, Epoch: a.Epoch}.Append(nil)
	c.mu.Unlock()

	// Sending resumes only after the reply is written, so the initiator
	// learns where to resume before any DATA on this path.
	c.control(p, func() error {
		if err := p.conn.WriteRecord(frame.TypeActivate, reply, 0); err != nil {
			return err
		}
		c.mu.Lock()
		if c.gen == gen {
			c.ready = true
			c.disarmResumeLocked()
		}
		c.mu.Unlock()
		c.kick()
		return nil
	})
}

// retire closes a replaced path after telling the peer why, so the peer
// drops it without treating it as a failure.
func (c *ResumableConn) retire(p *path) {
	c.control(p, func() error {
		body := frame.CloseBody{Code: frame.CloseRotateComplete}.Append(nil)
		_ = p.conn.WriteRecord(frame.TypeClose, body, 0)
		return errPathRetired
	})
}

// control queues fn for p's control loop without blocking. A full queue
// means the path no longer drains; the watchdog will drop it.
func (c *ResumableConn) control(p *path, fn func() error) {
	select {
	case p.ctrl <- fn:
	default:
		c.log.Debug("control queue full; record dropped", "path", p.id)
	}
}

// pathFailed removes p. If it was the active path, the initiator promotes
// the best standby; either side starts the resume timer.
func (c *ResumableConn) pathFailed(p *path, cause error) {
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
	p.markGone()
	c.mu.Lock()
	delete(c.paths, p.id)
	wasActive := c.active == p
	if wasActive {
		c.active, c.ready = nil, false
		c.gen++
		c.armResumeLocked()
	}
	if c.retiring == p {
		c.retiring = nil
	}
	closed := c.closed
	c.mu.Unlock()
	_ = p.conn.Close()
	if closed {
		return
	}

	if errors.Is(cause, errPathRetired) {
		c.log.Debug("path retired", "path", p.id, "via", p.meta)
	} else {
		c.log.Info("path down", "path", p.id, "via", p.meta, "active", wasActive, "err", cause)
	}
	if c.cfg.OnPathDown != nil {
		c.cfg.OnPathDown(p.info(wasActive), cause)
	}
	if wasActive && c.cfg.Role == Initiator {
		c.promoteStandby()
	}
}

// promoteStandby activates the standby with the lowest RTT, if any.
func (c *ResumableConn) promoteStandby() {
	c.mu.Lock()
	var best *path
	for _, p := range c.paths {
		if p.dead.Load() || p == c.retiring {
			continue
		}
		if best == nil || p.rank() < best.rank() {
			best = p
		}
	}
	c.mu.Unlock()
	if best != nil {
		c.log.Info("failover", "to_path", best.id, "via", best.meta)
		c.activate(best)
	}
}

// controlLoop performs p's control writes and sends its PINGs.
func (c *ResumableConn) controlLoop(p *path) {
	defer c.wg.Done()
	t := time.NewTimer(jitter(c.cfg.ProbeInterval))
	defer t.Stop()
	var buf [12]byte
	for {
		select {
		case <-c.done:
			return
		case <-p.gone:
			return
		case fn := <-p.ctrl:
			if err := fn(); err != nil {
				c.pathFailed(p, err)
				return
			}
		case <-t.C:
			p.pingSeq++
			body := frame.Ping{ID: p.pingSeq, SentUs: uint64(time.Now().UnixMicro())}.Append(buf[:0])
			if err := p.conn.WriteRecord(frame.TypePing, body, 0); err != nil {
				c.pathFailed(p, err)
				return
			}
			t.Reset(jitter(c.cfg.ProbeInterval))
		}
	}
}

// watchdog drops paths that have been silent for DeadAfter. It does no I/O
// itself, so a path whose writes hang is still noticed; closing the path
// then unblocks those writes.
func (c *ResumableConn) watchdog() {
	defer c.wg.Done()
	t := time.NewTicker(c.cfg.ProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		c.mu.Lock()
		var silent []*path
		for _, p := range c.paths {
			if time.Since(time.Unix(0, p.lastRecv.Load())) > c.cfg.DeadAfter {
				silent = append(silent, p)
			}
		}
		c.mu.Unlock()
		for _, p := range silent {
			c.pathFailed(p, errPathTimeout)
		}
	}
}

// jitter spreads d by ±20 % so probes of many paths do not align.
func jitter(d time.Duration) time.Duration {
	return d*4/5 + rand.N(d*2/5+1) //nolint:gosec // timing jitter, not a secret
}
