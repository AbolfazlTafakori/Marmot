package frame

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"marmot/internal/crypto"
)

// Conn is the encrypted record layer over one path's byte stream.
//
// WriteRecord is safe for concurrent use. ReadRecord must be called from a
// single goroutine; the returned body is valid until the next ReadRecord.
type Conn struct {
	rw io.ReadWriteCloser

	wmu   sync.Mutex
	keys  crypto.CipherPair
	plain []byte // scratch plaintext, guarded by wmu
	wire  []byte // scratch length+ciphertext, guarded by wmu

	recvBuf []byte  // reader-owned
	recvHdr [2]byte // reader-owned

	closeOnce sync.Once
	closeErr  error
}

// NewConn wraps rw with the given path keys.
func NewConn(rw io.ReadWriteCloser, keys crypto.CipherPair) *Conn {
	return &Conn{
		rw:      rw,
		keys:    keys,
		plain:   make([]byte, 0, MaxPlaintext),
		wire:    make([]byte, 0, 2+MaxPlaintext+tagSize),
		recvBuf: make([]byte, MaxPlaintext+tagSize),
	}
}

// WriteRecord encrypts and writes one record. pad zero bytes are appended
// inside the encryption so that record sizes can be shaped.
func (c *Conn) WriteRecord(t Type, body []byte, pad int) error {
	if pad < 0 || headerSize+len(body)+pad > MaxPlaintext {
		return ErrTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

	p := c.plain[:0]
	p = append(p, byte(t))
	p = binary.BigEndian.AppendUint16(p, uint16(pad))
	p = append(p, body...)
	for i := 0; i < pad; i++ {
		p = append(p, 0)
	}
	w := c.wire[:2]
	w, err := c.keys.Send.Encrypt(w, nil, p)
	if err != nil {
		return fmt.Errorf("encrypt record: %w", err)
	}
	binary.BigEndian.PutUint16(w, uint16(len(w)-2))
	c.plain, c.wire = p[:0], w[:0]
	if _, err := c.rw.Write(w); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	return nil
}

// AppendRecord encrypts one record and appends it, with its length
// prefix, to dst; WriteRaw sends a batch of them in one write. Records
// must reach the wire in the order they were built, so only a single
// writer may use this pair, and never concurrently with WriteRecord.
func (c *Conn) AppendRecord(dst []byte, t Type, body []byte, pad int) ([]byte, error) {
	if pad < 0 || headerSize+len(body)+pad > MaxPlaintext {
		return dst, ErrTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	p := c.plain[:0]
	p = append(p, byte(t))
	p = binary.BigEndian.AppendUint16(p, uint16(pad))
	p = append(p, body...)
	for i := 0; i < pad; i++ {
		p = append(p, 0)
	}
	start := len(dst)
	dst = append(dst, 0, 0)
	dst, err := c.keys.Send.Encrypt(dst, nil, p)
	if err != nil {
		return dst[:start], fmt.Errorf("encrypt record: %w", err)
	}
	binary.BigEndian.PutUint16(dst[start:], uint16(len(dst)-start-2))
	c.plain = p[:0]
	return dst, nil
}

// WriteRaw writes records built by AppendRecord.
func (c *Conn) WriteRaw(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.rw.Write(b); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	return nil
}

// ReadRecord reads and decrypts the next record.
func (c *Conn) ReadRecord() (Type, []byte, error) {
	if _, err := io.ReadFull(c.rw, c.recvHdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(c.recvHdr[:]))
	if n < headerSize+tagSize || n > len(c.recvBuf) {
		return 0, nil, ErrTooLarge
	}
	ct := c.recvBuf[:n]
	if _, err := io.ReadFull(c.rw, ct); err != nil {
		return 0, nil, err
	}
	pt, err := c.keys.Recv.Decrypt(ct[:0], nil, ct)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt record: %w", err)
	}
	t := Type(pt[0])
	pad := int(binary.BigEndian.Uint16(pt[1:3]))
	if headerSize+pad > len(pt) {
		return 0, nil, ErrShortBody
	}
	return t, pt[headerSize : len(pt)-pad], nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.rw.Close() })
	return c.closeErr
}
