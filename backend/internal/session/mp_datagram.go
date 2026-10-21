package session

import (
	"errors"
	"io"
	"os"
	"sync"

	"marmot/internal/crypto"
	"marmot/internal/frame"
)

// Datagrams of UDP flows (ADR-0019): when both sides keep CapDatagrams, a
// flow's payloads travel in DATAGRAM frames that are never resent. A
// payload too large for one packet goes on the stream, framed as in spec
// §6.1, so the receiver reads from both.

const (
	maxDgQueue    = 256     // datagrams waiting to be sent, per session
	maxDgQueueLen = 1 << 20 // and their bytes
	dgRecvQueue   = 256     // datagrams waiting to be read, per stream
)

// WriteDatagram sends one UDP payload on st: unreliably when the session
// allows it and the payload fits one packet, framed on the stream
// otherwise. scratch must hold 2+len(payload) bytes.
func WriteDatagram(st io.Writer, scratch, payload []byte) error {
	if ds, ok := st.(datagramStream); ok {
		return ds.writeDatagram(scratch, payload)
	}
	return frame.WriteDatagram(st, scratch, payload)
}

// ReadDatagram reads the next UDP payload of st, whichever way it came.
// buf must hold frame.MaxDatagram bytes.
func ReadDatagram(st io.Reader, buf []byte) (int, error) {
	if ds, ok := st.(datagramStream); ok {
		return ds.readDatagram(buf)
	}
	return frame.ReadDatagram(st, buf)
}

// datagramStream is a stream that can carry unreliable datagrams.
type datagramStream interface {
	writeDatagram(scratch, payload []byte) error
	readDatagram(buf []byte) (int, error)
}

// dgItem is a datagram waiting to be sent.
type dgItem struct {
	sid  uint32
	data []byte
}

// dgState is a v2 stream's datagram side.
type dgState struct {
	in       chan []byte
	pumpOnce sync.Once
	pumpErr  error
	pumpDone chan struct{}
}

func (s *MPSession) datagramsOK() bool { return s.caps&crypto.CapDatagrams != 0 }

// dgBudgetLocked is the largest payload that fits one packet on every
// path that could carry it.
func (s *MPSession) dgBudgetLocked() int {
	budget := 0
	for _, p := range s.order {
		if !p.healthy() {
			continue
		}
		room := p.maxBody - 8 - frame.DatagramFrameOverhead
		if p.datagram {
			room = p.maxBody - fecReserve - frame.DatagramFrameOverhead
		}
		if budget == 0 || room < budget {
			budget = room
		}
	}
	return budget
}

func (st *mpStream) writeDatagram(scratch, payload []byte) error {
	s := st.s
	s.mu.Lock()
	if err := st.writeErrLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	if !s.datagramsOK() || len(payload) > s.dgBudgetLocked() {
		s.mu.Unlock()
		return frame.WriteDatagram(st, scratch, payload)
	}
	for len(s.dgQ) >= maxDgQueue || (s.dgBytes+len(payload) > maxDgQueueLen && len(s.dgQ) > 0) {
		s.dgBytes -= len(s.dgQ[0].data) // the oldest is the least useful
		s.dgQ[0] = dgItem{}
		s.dgQ = s.dgQ[1:]
	}
	s.dgQ = append(s.dgQ, dgItem{sid: st.id, data: append([]byte(nil), payload...)})
	s.dgBytes += len(payload)
	s.mu.Unlock()
	s.wakeWriters()
	return nil
}

func (st *mpStream) readDatagram(buf []byte) (int, error) {
	s := st.s
	if !s.datagramsOK() {
		return frame.ReadDatagram(st, buf)
	}
	st.dg.pumpOnce.Do(func() { go st.pumpStreamDatagrams() })
	select {
	case d := <-st.dg.in:
		return copy(buf, d), nil
	default:
	}
	select {
	case d := <-st.dg.in:
		return copy(buf, d), nil
	case <-st.dg.pumpDone:
		select {
		case d := <-st.dg.in: // drain what arrived before the end
			return copy(buf, d), nil
		default:
		}
		return 0, st.dg.pumpErr
	case <-st.rdl.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

// pumpStreamDatagrams moves datagrams framed on the stream (too large for
// a packet) into the same queue as DATAGRAM frames; the stream's end ends
// the flow.
func (st *mpStream) pumpStreamDatagrams() {
	defer close(st.dg.pumpDone)
	buf := make([]byte, frame.MaxDatagram)
	for {
		n, err := frame.ReadDatagram(st, buf)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			st.dg.pumpErr = err
			return
		}
		st.dg.in <- append([]byte(nil), buf[:n]...)
	}
}

// onDatagramLocked queues a received DATAGRAM frame for its stream; with
// no room it is dropped, as the network would.
func (s *MPSession) onDatagramLocked(f *frame.Frame) {
	st := s.streams[f.StreamID]
	if st == nil || st.readClosed || st.resetIn {
		return
	}
	select {
	case st.dg.in <- append([]byte(nil), f.Data...):
	default:
	}
}

// appendDatagramsLocked appends queued datagrams that fit; they are never
// resent, so their frames are recorded only to count in flight.
func (s *MPSession) appendDatagramsLocked(b []byte, fr []sentFrame, limit int) ([]byte, []sentFrame) {
	kept := s.dgQ[:0]
	for _, it := range s.dgQ {
		st := s.streams[it.sid]
		if st == nil || st.sendAborted() {
			s.dgBytes -= len(it.data)
			continue
		}
		// Not before the stream's header is out: a receiver that does not
		// know the stream yet drops its datagrams.
		if st.sentOff == 0 || limit-len(b) < frame.DatagramFrameOverhead+len(it.data) {
			kept = append(kept, it)
			continue
		}
		b = frame.AppendDatagram(b, it.sid, it.data)
		s.dgBytes -= len(it.data)
		fr = append(fr, sentFrame{kind: fkDatagram, sid: it.sid})
	}
	clear(s.dgQ[len(kept):])
	s.dgQ = kept
	return b, fr
}

// The opener's wrapper reads the reply byte first, then passes on.
func (s *openedStream) writeDatagram(scratch, payload []byte) error {
	if ds, ok := s.st.(datagramStream); ok {
		return ds.writeDatagram(scratch, payload)
	}
	return frame.WriteDatagram(s.st, scratch, payload)
}

func (s *openedStream) readDatagram(buf []byte) (int, error) {
	if err := s.readReply(); err != nil {
		return 0, err
	}
	if ds, ok := s.st.(datagramStream); ok {
		return ds.readDatagram(buf)
	}
	return frame.ReadDatagram(s.st, buf)
}
