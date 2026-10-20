package session

import (
	"errors"
	"time"

	"marmot/internal/frame"
)

// sendLoop is the only goroutine that sends DATA and ACK records.
func (c *ResumableConn) sendLoop() {
	defer c.wg.Done()
	t := time.NewTicker(ackInterval)
	defer t.Stop()
	scratch := make([]byte, 0, 8+frame.MaxDataPayload)
	for {
		tick := false
		select {
		case <-c.done:
			return
		case <-c.wake:
		case <-t.C:
			tick = true
		}
		c.flush(scratch, tick)
	}
}

// flush sends pending ACKs and data on the active path until there is
// nothing left or the path changes.
func (c *ResumableConn) flush(scratch []byte, tick bool) {
	for {
		c.mu.Lock()
		p := c.active
		if p == nil || !c.ready || c.closed {
			c.mu.Unlock()
			return
		}
		if c.consumedOff > c.ackSentOff && (tick || c.consumedOff-c.ackSentOff >= ackEvery) {
			off := c.consumedOff
			c.mu.Unlock()
			if err := p.conn.WriteRecord(frame.TypeAck, frame.AppendOffset(scratch[:0], off), 0); err != nil {
				c.pathFailed(p, err)
				return
			}
			c.mu.Lock()
			c.ackSentOff = max(c.ackSentOff, off)
			c.mu.Unlock()
			tick = false
			continue
		}
		if c.sentOff >= c.writeOff {
			c.mu.Unlock()
			return
		}
		start, gen := c.sentOff, c.gen
		n := int(min(c.writeOff-start, frame.MaxDataPayload))
		body := frame.AppendOffset(scratch[:0], start)
		body = c.sbuf.AppendRange(body, int(start-c.ackedOff), n)
		c.mu.Unlock()

		if err := p.conn.WriteRecord(frame.TypeData, body, 0); err != nil {
			c.pathFailed(p, err)
			return
		}
		p.bytesSent.Add(uint64(n))
		c.mu.Lock()
		// An ACTIVATE may have moved the resend point meanwhile; then this
		// write must not advance it.
		if c.gen == gen && c.sentOff == start {
			c.sentOff = start + uint64(n)
		}
		c.mu.Unlock()
	}
}

// readLoop reads and dispatches records from p until it fails.
func (c *ResumableConn) readLoop(p *path) {
	defer c.wg.Done()
	for {
		typ, body, err := p.conn.ReadRecord()
		if err != nil {
			c.pathFailed(p, err)
			return
		}
		p.lastRecv.Store(time.Now().UnixNano())
		if err := c.dispatch(p, typ, body); err != nil {
			if errors.Is(err, errProtocol) {
				c.log.Warn("protocol error on path", "path", p.id, "type", typ, "err", err)
			}
			c.pathFailed(p, err)
			return
		}
	}
}

func (c *ResumableConn) dispatch(p *path, typ frame.Type, body []byte) error {
	switch typ {
	case frame.TypeData:
		off, data, err := frame.ParseData(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		p.bytesRecv.Add(uint64(len(data)))
		c.deliver(off, data)
	case frame.TypeAck:
		off, err := frame.ParseAck(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		c.acked(off)
	case frame.TypePing:
		pg, err := frame.ParsePing(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		c.control(p, func() error {
			var buf [12]byte
			return p.conn.WriteRecord(frame.TypePong, pg.Append(buf[:0]), 0)
		})
	case frame.TypePong:
		pg, err := frame.ParsePing(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		p.observeRTT(time.Duration(time.Now().UnixMicro()-int64(pg.SentUs)) * time.Microsecond)
	case frame.TypeActivate:
		a, err := frame.ParseActivate(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		c.onActivate(p, a)
	case frame.TypeRotate:
		// Advisory in v1: rotation is carried out by ACTIVATE.
	case frame.TypeClose:
		cb, err := frame.ParseClose(body)
		if err != nil {
			return errors.Join(errProtocol, err)
		}
		if cb.Code == frame.CloseRotateComplete {
			return errPathRetired
		}
		c.log.Info("session closed by peer", "code", cb.Code, "reason", cb.Reason)
		c.shutdown(ErrClosedByPeer, frame.CloseNormal, false)
		return ErrClosedByPeer
	default:
		return errors.Join(errProtocol, frame.ErrUnknownType)
	}
	return nil
}

// deliver appends the new part of a DATA record to the receive buffer.
// Bytes below recvOff are duplicates from a resend; a record beyond
// recvOff can only be a leftover from a failed path, and the active path
// will resend it.
func (c *ResumableConn) deliver(off uint64, data []byte) {
	c.mu.Lock()
	if off > c.recvOff {
		c.mu.Unlock()
		return
	}
	skip := c.recvOff - off
	if skip >= uint64(len(data)) {
		c.mu.Unlock()
		return
	}
	data = data[skip:]
	if c.rbuf.Free() < len(data) {
		c.mu.Unlock()
		c.log.Warn("peer exceeded the receive window")
		c.shutdown(errProtocol, frame.CloseProtocolError, true)
		return
	}
	c.rbuf.Write(data)
	c.recvOff += uint64(len(data))
	c.cond.Broadcast()
	c.mu.Unlock()
}

// acked frees the send buffer up to off.
func (c *ResumableConn) acked(off uint64) {
	c.mu.Lock()
	if off > c.writeOff {
		c.mu.Unlock()
		c.shutdown(errProtocol, frame.CloseProtocolError, true)
		return
	}
	if off > c.ackedOff {
		c.sbuf.Discard(int(off - c.ackedOff))
		c.ackedOff = off
		c.sentOff = max(c.sentOff, off)
		c.cond.Broadcast()
	}
	c.mu.Unlock()
}
