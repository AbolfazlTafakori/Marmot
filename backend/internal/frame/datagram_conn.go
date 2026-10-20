package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/flynn/noise"

	"marmot/internal/crypto"
)

// PacketIO moves whole datagrams. transport.PacketConn satisfies it.
type PacketIO interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) error
	Close() error
}

// replayWindow is the number of nonces below the highest one seen that
// are still accepted (spec §4.2).
const replayWindow = 1024

// nonceSize is the explicit nonce in front of every datagram record.
const nonceSize = 8

// DatagramOverhead is what a datagram record adds to its body.
const DatagramOverhead = nonceSize + headerSize + tagSize

// ErrDatagramTooLarge means a record does not fit the path's datagrams.
var ErrDatagramTooLarge = errors.New("frame: record larger than the path's datagram size")

// DatagramConn is the encrypted record layer over one datagram path
// (spec §4.2): one record per datagram, explicit nonce, replay window.
// Records may be lost, duplicated or reordered; this layer only drops
// replays and forgeries.
//
// WriteRecord is safe for concurrent use. ReadRecord must be called from a
// single goroutine; the returned body is valid until the next ReadRecord.
type DatagramConn struct {
	pc      PacketIO
	maxSize int // largest datagram

	wmu   sync.Mutex
	send  noise.Cipher
	nonce uint64
	plain []byte
	wire  []byte

	recv    noise.Cipher
	rbuf    []byte
	highest uint64
	seen    [replayWindow / 64]uint64 // bit i: highest-i was seen
	any     bool

	// Dropped counts datagrams that failed authentication or were replays;
	// only the reader goroutine writes it.
	Dropped uint64

	closeOnce sync.Once
	closeErr  error
}

// NewDatagramConn wraps pc with the path keys. maxSize is the largest
// datagram the path carries. It takes the ciphers out of keys; keys must
// not be used for a stream record layer afterwards.
func NewDatagramConn(pc PacketIO, keys crypto.CipherPair, maxSize int) *DatagramConn {
	return &DatagramConn{
		pc:      pc,
		maxSize: maxSize,
		send:    keys.Send.Cipher(),
		recv:    keys.Recv.Cipher(),
		plain:   make([]byte, 0, maxSize),
		wire:    make([]byte, 0, maxSize),
		rbuf:    make([]byte, max(maxSize, 64<<10)),
	}
}

// MaxBody is the largest record body this path can carry unpadded.
func (c *DatagramConn) MaxBody() int { return c.maxSize - DatagramOverhead }

// WriteRecord encrypts and sends one record as one datagram.
func (c *DatagramConn) WriteRecord(t Type, body []byte, pad int) error {
	if pad < 0 || DatagramOverhead+len(body)+pad > c.maxSize {
		return ErrDatagramTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	p := c.plain[:0]
	p = append(p, byte(t))
	p = binary.BigEndian.AppendUint16(p, uint16(pad))
	p = append(p, body...)
	for range pad {
		p = append(p, 0)
	}
	n := c.nonce
	c.nonce++
	w := binary.BigEndian.AppendUint64(c.wire[:0], n)
	w = c.send.Encrypt(w, n, nil, p)
	c.plain, c.wire = p[:0], w[:0]
	if err := c.pc.WritePacket(w); err != nil {
		return fmt.Errorf("write datagram: %w", err)
	}
	return nil
}

// ReadRecord returns the next authentic, fresh record. Forged, damaged
// and replayed datagrams are skipped.
func (c *DatagramConn) ReadRecord() (Type, []byte, error) {
	for {
		n, err := c.pc.ReadPacket(c.rbuf)
		if err != nil {
			return 0, nil, err
		}
		d := c.rbuf[:n]
		if len(d) < nonceSize+headerSize+tagSize {
			c.Dropped++
			continue
		}
		nonce := binary.BigEndian.Uint64(d)
		if !c.fresh(nonce) {
			c.Dropped++
			continue
		}
		pt, err := c.recv.Decrypt(d[nonceSize:nonceSize], nonce, nil, d[nonceSize:])
		if err != nil {
			c.Dropped++
			continue
		}
		pad := int(binary.BigEndian.Uint16(pt[1:3]))
		if headerSize+pad > len(pt) {
			c.Dropped++
			continue
		}
		c.mark(nonce)
		return Type(pt[0]), pt[headerSize : len(pt)-pad], nil
	}
}

// fresh reports whether nonce is inside the window and not seen yet.
func (c *DatagramConn) fresh(n uint64) bool {
	if !c.any || n > c.highest {
		return true
	}
	back := c.highest - n
	if back >= replayWindow {
		return false
	}
	return c.seen[back/64]&(1<<(back%64)) == 0
}

// mark records nonce n as seen, sliding the window if it is the highest.
func (c *DatagramConn) mark(n uint64) {
	if !c.any {
		c.any, c.highest = true, n
		c.seen[0] = 1
		return
	}
	if n > c.highest {
		c.shift(n - c.highest)
		c.highest = n
	}
	back := c.highest - n
	c.seen[back/64] |= 1 << (back % 64)
}

// shift moves the window up by k: bit i becomes bit i+k.
func (c *DatagramConn) shift(k uint64) {
	if k >= replayWindow {
		c.seen = [replayWindow / 64]uint64{}
		return
	}
	words, bits := int(k/64), k%64
	for i := len(c.seen) - 1; i >= 0; i-- {
		var v uint64
		if j := i - words; j >= 0 {
			v = c.seen[j] << bits
			if bits > 0 && j > 0 {
				v |= c.seen[j-1] >> (64 - bits)
			}
		}
		c.seen[i] = v
	}
}

// Close closes the underlying datagram connection.
func (c *DatagramConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.pc.Close() })
	return c.closeErr
}
