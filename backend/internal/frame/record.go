// Package frame implements the encrypted record layer of a path and the
// codecs for record bodies (docs/spec/frame.md §4).
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Type identifies a record.
type Type uint8

// Record types.
const (
	TypeData     Type = 0x01
	TypeAck      Type = 0x02
	TypePing     Type = 0x03
	TypePong     Type = 0x04
	TypeActivate Type = 0x05
	TypeRotate   Type = 0x06
	TypeClose    Type = 0x07
)

func (t Type) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeAck:
		return "ACK"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeActivate:
		return "ACTIVATE"
	case TypeRotate:
		return "ROTATE"
	case TypeClose:
		return "CLOSE"
	default:
		return fmt.Sprintf("TYPE(0x%02x)", uint8(t))
	}
}

// Size limits.
const (
	MaxPlaintext = 16 << 10
	tagSize      = 16
	headerSize   = 1 + 2 // type + pad_len
	// MaxBody is the largest body that fits in one record without padding.
	MaxBody = MaxPlaintext - headerSize
	// MaxDataPayload is the largest user payload in one DATA record.
	MaxDataPayload = MaxBody - 8
)

// Errors returned by codecs.
var (
	ErrShortBody   = errors.New("frame: body too short")
	ErrTooLarge    = errors.New("frame: record too large")
	ErrUnknownType = errors.New("frame: unknown record type")
)

// Close codes (spec §9).
const (
	CloseNormal         uint16 = 0
	CloseProtocolError  uint16 = 1
	CloseAuthFailed     uint16 = 2
	CloseRotateComplete uint16 = 3
	CloseShutdown       uint16 = 4
	CloseOverloaded     uint16 = 5
	CloseRevoked        uint16 = 6
)

// AppendOffset encodes an ACK body or the header of a DATA body.
func AppendOffset(b []byte, off uint64) []byte { return binary.BigEndian.AppendUint64(b, off) }

// ParseData splits a DATA body into its offset and payload.
func ParseData(body []byte) (uint64, []byte, error) {
	if len(body) < 8 {
		return 0, nil, ErrShortBody
	}
	return binary.BigEndian.Uint64(body), body[8:], nil
}

// ParseAck decodes an ACK body.
func ParseAck(body []byte) (uint64, error) {
	if len(body) != 8 {
		return 0, ErrShortBody
	}
	return binary.BigEndian.Uint64(body), nil
}

// Ping is the body of PING and PONG records.
type Ping struct {
	ID     uint32
	SentUs uint64
}

// Append encodes p.
func (p Ping) Append(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, p.ID)
	return binary.BigEndian.AppendUint64(b, p.SentUs)
}

// ParsePing decodes a PING/PONG body.
func ParsePing(body []byte) (Ping, error) {
	if len(body) != 12 {
		return Ping{}, ErrShortBody
	}
	return Ping{ID: binary.BigEndian.Uint32(body), SentUs: binary.BigEndian.Uint64(body[4:])}, nil
}

// Activate is the body of an ACTIVATE record: "this path is now active at
// switch epoch Epoch; resend to me from Offset".
type Activate struct {
	Offset uint64
	Epoch  uint32
}

// Append encodes a.
func (a Activate) Append(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, a.Offset)
	return binary.BigEndian.AppendUint32(b, a.Epoch)
}

// ParseActivate decodes an ACTIVATE body.
func ParseActivate(body []byte) (Activate, error) {
	if len(body) != 12 {
		return Activate{}, ErrShortBody
	}
	return Activate{Offset: binary.BigEndian.Uint64(body), Epoch: binary.BigEndian.Uint32(body[8:])}, nil
}

// CloseBody is the body of a CLOSE record.
type CloseBody struct {
	Code   uint16
	Reason string
}

// Append encodes c, truncating the reason to 255 bytes.
func (c CloseBody) Append(b []byte) []byte {
	r := c.Reason
	if len(r) > 255 {
		r = r[:255]
	}
	b = binary.BigEndian.AppendUint16(b, c.Code)
	b = append(b, byte(len(r)))
	return append(b, r...)
}

// ParseClose decodes a CLOSE body.
func ParseClose(body []byte) (CloseBody, error) {
	if len(body) < 3 || len(body) != 3+int(body[2]) {
		return CloseBody{}, ErrShortBody
	}
	return CloseBody{Code: binary.BigEndian.Uint16(body), Reason: string(body[3:])}, nil
}
