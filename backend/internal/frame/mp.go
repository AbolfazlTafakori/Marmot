package frame

import (
	"encoding/binary"
	"errors"
	"math"
)

// Session v2 record types (spec §11.2).
const (
	TypePacket    Type = 0x80
	TypeRepair    Type = 0x81
	TypePacketFEC Type = 0x82
)

// Kind identifies a frame inside a v2 packet (spec §11.3).
type Kind uint8

// v2 frame types.
const (
	FramePing          Kind = 0x01
	FrameAck           Kind = 0x02
	FrameStream        Kind = 0x03
	FrameReset         Kind = 0x04
	FrameStop          Kind = 0x05
	FrameMaxStreamData Kind = 0x06
	FrameMaxData       Kind = 0x07
)

// MaxAckRanges bounds the ranges of one ACK frame.
const MaxAckRanges = 32

// Errors of the v2 codecs.
var (
	ErrBadVarint    = errors.New("frame: bad varint")
	ErrBadFrame     = errors.New("frame: malformed frame")
	ErrUnknownFrame = errors.New("frame: unknown frame type")
)

// AckRange is an inclusive range of packet numbers.
type AckRange struct{ Lo, Hi uint64 }

// Frame is one decoded v2 frame. Only the fields of its Type are set.
type Frame struct {
	Type Kind

	// ACK: ranges in descending order, disjoint and not adjacent.
	Ranges  []AckRange
	DelayUs uint64

	// STREAM, RESET, STOP, MAX_STREAM_DATA.
	StreamID uint32
	// STREAM.
	Offset uint64
	Fin    bool
	Data   []byte // aliases the packet

	// RESET: Code and Final, the stream's final size. MAX_STREAM_DATA,
	// MAX_DATA: Max.
	Code  uint64
	Final uint64
	Max   uint64
}

// AppendPacketHeader starts a PKT body.
func AppendPacketHeader(b []byte, pn uint64) []byte { return binary.BigEndian.AppendUint64(b, pn) }

// ParsePacket splits a PKT body into its number and frames.
func ParsePacket(body []byte) (uint64, []byte, error) {
	if len(body) < 8 {
		return 0, nil, ErrShortBody
	}
	return binary.BigEndian.Uint64(body), body[8:], nil
}

// AppendPing appends a PING frame.
func AppendPing(b []byte) []byte { return append(b, byte(FramePing)) }

// AppendAck appends an ACK frame. ranges must be in descending order,
// disjoint and not adjacent; at most MaxAckRanges are encoded, the
// highest first.
func AppendAck(b []byte, delayUs uint64, ranges []AckRange) []byte {
	ranges = ranges[:min(len(ranges), MaxAckRanges)]
	b = append(b, byte(FrameAck))
	b = binary.AppendUvarint(b, ranges[0].Hi)
	b = binary.AppendUvarint(b, delayUs)
	b = binary.AppendUvarint(b, uint64(len(ranges)-1))
	b = binary.AppendUvarint(b, ranges[0].Hi-ranges[0].Lo)
	for i := 1; i < len(ranges); i++ {
		b = binary.AppendUvarint(b, ranges[i-1].Lo-ranges[i].Hi-2)
		b = binary.AppendUvarint(b, ranges[i].Hi-ranges[i].Lo)
	}
	return b
}

// AppendStream appends a STREAM frame.
func AppendStream(b []byte, id uint32, off uint64, fin bool, data []byte) []byte {
	return append(AppendStreamHeader(b, id, off, fin, len(data)), data...)
}

// AppendStreamHeader appends a STREAM frame without its n data bytes,
// which the caller appends next.
func AppendStreamHeader(b []byte, id uint32, off uint64, fin bool, n int) []byte {
	b = append(b, byte(FrameStream))
	b = binary.AppendUvarint(b, uint64(id))
	b = binary.AppendUvarint(b, off)
	if fin {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return binary.AppendUvarint(b, uint64(n))
}

// StreamOverhead is the size of a STREAM frame without its data.
func StreamOverhead(id uint32, off uint64, n int) int {
	return 1 + uvarintLen(uint64(id)) + uvarintLen(off) + 1 + uvarintLen(uint64(n))
}

// AppendReset appends a RESET frame: the sender abandons its direction
// of the stream after final bytes.
func AppendReset(b []byte, id uint32, code, final uint64) []byte {
	b = append(b, byte(FrameReset))
	b = binary.AppendUvarint(b, uint64(id))
	b = binary.AppendUvarint(b, code)
	return binary.AppendUvarint(b, final)
}

// AppendStop appends a STOP frame.
func AppendStop(b []byte, id uint32) []byte {
	return binary.AppendUvarint(append(b, byte(FrameStop)), uint64(id))
}

// AppendMaxStreamData appends a MAX_STREAM_DATA frame.
func AppendMaxStreamData(b []byte, id uint32, limit uint64) []byte {
	b = append(b, byte(FrameMaxStreamData))
	b = binary.AppendUvarint(b, uint64(id))
	return binary.AppendUvarint(b, limit)
}

// AppendMaxData appends a MAX_DATA frame.
func AppendMaxData(b []byte, limit uint64) []byte {
	return binary.AppendUvarint(append(b, byte(FrameMaxData)), limit)
}

// ParseFrame decodes the first frame of b into f and returns the rest.
// f.Ranges is reused; f.Data aliases b.
func ParseFrame(b []byte, f *Frame) ([]byte, error) {
	if len(b) == 0 {
		return nil, ErrShortBody
	}
	ranges := f.Ranges[:0]
	*f = Frame{Type: Kind(b[0]), Ranges: ranges}
	r := reader{b: b[1:]}
	switch f.Type {
	case FramePing:
	case FrameAck:
		parseAck(&r, f)
	case FrameStream:
		f.StreamID = r.streamID()
		f.Offset = r.uvarint()
		switch fin := r.byte(); fin {
		case 0, 1:
			f.Fin = fin == 1
		default:
			r.fail(ErrBadFrame)
		}
		n := r.uvarint()
		f.Data = r.bytes(n)
		if r.err == nil && f.Offset > math.MaxUint64-n {
			r.fail(ErrBadFrame)
		}
	case FrameReset:
		f.StreamID = r.streamID()
		f.Code = r.uvarint()
		f.Final = r.uvarint()
	case FrameStop:
		f.StreamID = r.streamID()
	case FrameMaxStreamData:
		f.StreamID = r.streamID()
		f.Max = r.uvarint()
	case FrameMaxData:
		f.Max = r.uvarint()
	default:
		return nil, ErrUnknownFrame
	}
	if r.err != nil {
		return nil, r.err
	}
	return r.b, nil
}

func parseAck(r *reader, f *Frame) {
	largest := r.uvarint()
	f.DelayUs = r.uvarint()
	count := r.uvarint()
	first := r.uvarint()
	if r.err != nil {
		return
	}
	if count >= MaxAckRanges || first > largest {
		r.fail(ErrBadFrame)
		return
	}
	lo := largest - first
	f.Ranges = append(f.Ranges, AckRange{Lo: lo, Hi: largest})
	for range count {
		gap, n := r.uvarint(), r.uvarint()
		if r.err != nil {
			return
		}
		if lo < gap+2 || lo-gap-2 < n {
			r.fail(ErrBadFrame)
			return
		}
		hi := lo - gap - 2
		lo = hi - n
		f.Ranges = append(f.Ranges, AckRange{Lo: lo, Hi: hi})
	}
}

// reader decodes fields and keeps the first error.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
	r.b = nil
}

func (r *reader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.fail(ErrBadVarint)
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) streamID() uint32 {
	v := r.uvarint()
	if v > math.MaxUint32 {
		r.fail(ErrBadFrame)
		return 0
	}
	return uint32(v)
}

func (r *reader) byte() byte {
	if r.err != nil {
		return 0
	}
	if len(r.b) == 0 {
		r.fail(ErrShortBody)
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *reader) bytes(n uint64) []byte {
	if r.err != nil {
		return nil
	}
	if n > uint64(len(r.b)) {
		r.fail(ErrShortBody)
		return nil
	}
	out := r.b[:n:n]
	r.b = r.b[n:]
	return out
}

func uvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
