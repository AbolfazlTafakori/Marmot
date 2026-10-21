package crypto

import (
	"encoding/binary"
	"errors"

	"marmot/internal/core"
)

// ProtocolVersion is the wire protocol version carried in Hello.
const ProtocolVersion = 1

// SessionIDSize is the length of a session identifier.
const SessionIDSize = 16

// SessionID identifies a session across all of its paths.
type SessionID [SessionIDSize]byte

// Hello flags.
const (
	FlagJoin   uint8 = 1 << 0 // join an existing session with a new path
	FlagRotate uint8 = 1 << 1 // make-before-break replacement path
)

// Capability bits.
const (
	CapUDP       uint32 = 1 << 0
	CapRelay     uint32 = 1 << 1
	CapVIPDup    uint32 = 1 << 2
	CapMultipath uint32 = 1 << 3
	CapDatagrams uint32 = 1 << 4 // unreliable datagrams for UDP flows (ADR-0019)
)

// Hello is the initiator's encrypted handshake payload.
type Hello struct {
	Version   uint8
	Flags     uint8
	SessionID SessionID
	Timestamp int64 // unix milliseconds
	Nonce     [16]byte
	NodeID    core.NodeID
	Caps      uint32
}

// Welcome status codes.
const (
	StatusOK             uint8 = 0
	StatusUnknownSession uint8 = 1
	StatusRejected       uint8 = 2
	StatusOverloaded     uint8 = 3
)

// Welcome is the responder's encrypted handshake payload.
type Welcome struct {
	Status       uint8
	Caps         uint32
	ResumeOffset uint64
}

var errShortPayload = errors.New("handshake payload too short")

const helloFixed = 1 + 1 + SessionIDSize + 8 + 16 + 1 + 4

// MarshalBinary encodes the Hello payload.
func (h *Hello) MarshalBinary() []byte {
	b := make([]byte, 0, helloFixed+len(h.NodeID))
	b = append(b, h.Version, h.Flags)
	b = append(b, h.SessionID[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(h.Timestamp))
	b = append(b, h.Nonce[:]...)
	b = append(b, byte(len(h.NodeID)))
	b = append(b, h.NodeID...)
	return binary.BigEndian.AppendUint32(b, h.Caps)
}

// UnmarshalBinary decodes a Hello payload.
func (h *Hello) UnmarshalBinary(b []byte) error {
	if len(b) < helloFixed {
		return errShortPayload
	}
	h.Version, h.Flags = b[0], b[1]
	b = b[2:]
	copy(h.SessionID[:], b)
	b = b[SessionIDSize:]
	h.Timestamp = int64(binary.BigEndian.Uint64(b))
	b = b[8:]
	copy(h.Nonce[:], b)
	b = b[16:]
	n := int(b[0])
	b = b[1:]
	if len(b) != n+4 {
		return errShortPayload
	}
	id, err := core.ParseNodeID(string(b[:n]))
	if err != nil {
		return err
	}
	h.NodeID = id
	h.Caps = binary.BigEndian.Uint32(b[n:])
	return nil
}

const welcomeSize = 1 + 4 + 8

// MarshalBinary encodes the Welcome payload.
func (w *Welcome) MarshalBinary() []byte {
	b := make([]byte, 0, welcomeSize)
	b = append(b, w.Status)
	b = binary.BigEndian.AppendUint32(b, w.Caps)
	return binary.BigEndian.AppendUint64(b, w.ResumeOffset)
}

// UnmarshalBinary decodes a Welcome payload.
func (w *Welcome) UnmarshalBinary(b []byte) error {
	if len(b) != welcomeSize {
		return errShortPayload
	}
	w.Status = b[0]
	w.Caps = binary.BigEndian.Uint32(b[1:])
	w.ResumeOffset = binary.BigEndian.Uint64(b[5:])
	return nil
}
