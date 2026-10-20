package frame

import (
	"encoding/binary"
	"io"
)

// MaxDatagram is the largest UDP payload carried inside a stream.
const MaxDatagram = 0xFFFF

// WriteDatagram writes one UDP payload to a stream as len:u16 | payload
// (spec §6.1). scratch must have room for 2+len(payload) bytes; it lets
// the header and payload go out in one Write without allocating.
func WriteDatagram(w io.Writer, scratch, payload []byte) error {
	if len(payload) > MaxDatagram {
		return ErrTooLarge
	}
	b := binary.BigEndian.AppendUint16(scratch[:0], uint16(len(payload)))
	b = append(b, payload...)
	_, err := w.Write(b)
	return err
}

// ReadDatagram reads one framed UDP payload into buf, which must hold
// MaxDatagram bytes, and returns its length.
func ReadDatagram(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		return 0, ErrTooLarge
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
