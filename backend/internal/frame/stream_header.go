package frame

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"marmot/internal/core"
)

// StreamHeaderVersion is the version byte of StreamHeader.
const StreamHeaderVersion = 1

// MaxRouteHops bounds the relay route carried in a header.
const MaxRouteHops = 4

// Stream reply codes (spec §6).
const (
	ReplyOK          byte = 0
	ReplyRefused     byte = 1
	ReplyUnreachable byte = 2
	ReplyDenied      byte = 3
)

// ErrBadStreamHeader is returned for malformed stream headers.
var ErrBadStreamHeader = errors.New("frame: bad stream header")

// StreamHeader is written at the start of every mux stream.
type StreamHeader struct {
	Proto      core.Proto
	Class      core.Class
	TargetPort uint16
	Client     netip.AddrPort
	Route      []core.NodeID // remaining relay hops; empty = deliver locally
}

// MarshalBinary encodes the header.
func (h *StreamHeader) MarshalBinary() ([]byte, error) {
	if !h.Proto.Valid() || !h.Class.Valid() || h.TargetPort == 0 || len(h.Route) > MaxRouteHops {
		return nil, ErrBadStreamHeader
	}
	addr := h.Client.Addr().Unmap()
	if !addr.IsValid() {
		return nil, ErrBadStreamHeader
	}
	b := make([]byte, 0, 32)
	b = append(b, StreamHeaderVersion, byte(h.Proto), byte(h.Class))
	b = binary.BigEndian.AppendUint16(b, h.TargetPort)
	if addr.Is4() {
		b = append(b, 4)
	} else {
		b = append(b, 6)
	}
	b = append(b, addr.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, h.Client.Port())
	b = append(b, byte(len(h.Route)))
	for _, hop := range h.Route {
		if len(hop) == 0 || len(hop) > core.MaxNodeIDLen {
			return nil, ErrBadStreamHeader
		}
		b = append(b, byte(len(hop)))
		b = append(b, hop...)
	}
	return b, nil
}

// ReadStreamHeader reads and validates a header from r.
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	var h StreamHeader
	var fixed [6]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return h, err
	}
	if fixed[0] != StreamHeaderVersion {
		return h, ErrBadStreamHeader
	}
	h.Proto, h.Class = core.Proto(fixed[1]), core.Class(fixed[2])
	h.TargetPort = binary.BigEndian.Uint16(fixed[3:5])
	if !h.Proto.Valid() || !h.Class.Valid() || h.TargetPort == 0 {
		return h, ErrBadStreamHeader
	}
	var ipLen int
	switch fixed[5] {
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return h, ErrBadStreamHeader
	}
	var buf [16 + 2 + 1]byte
	if _, err := io.ReadFull(r, buf[:ipLen+3]); err != nil {
		return h, err
	}
	addr, _ := netip.AddrFromSlice(buf[:ipLen])
	if addr.Is4In6() {
		return h, ErrBadStreamHeader // encoders always send these as IPv4
	}
	h.Client = netip.AddrPortFrom(addr, binary.BigEndian.Uint16(buf[ipLen:]))
	hops := int(buf[ipLen+2])
	if hops > MaxRouteHops {
		return h, ErrBadStreamHeader
	}
	for i := 0; i < hops; i++ {
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return h, err
		}
		id := make([]byte, l[0])
		if _, err := io.ReadFull(r, id); err != nil {
			return h, err
		}
		nid, err := core.ParseNodeID(string(id))
		if err != nil {
			return h, ErrBadStreamHeader
		}
		h.Route = append(h.Route, nid)
	}
	return h, nil
}
