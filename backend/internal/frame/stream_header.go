package frame

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"marmot/internal/core"
)

// Stream header versions: 1 for relay streams, 2 for exit streams that
// carry a destination (spec §6.2, ADR-0010).
const (
	StreamHeaderVersion     = 1
	StreamHeaderVersionExit = 2
)

// Destination address types of an exit stream.
const (
	dstIPv4   = 1
	dstDomain = 3
	dstIPv6   = 4
)

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
	Dest       Destination   // set for exit streams; zero for relay streams
}

// Destination is where an exit stream goes: an IP address or a domain
// name, and a port.
type Destination struct {
	IP   netip.Addr
	Host string
	Port uint16
}

// IsZero reports whether no destination is set.
func (d Destination) IsZero() bool { return !d.IP.IsValid() && d.Host == "" && d.Port == 0 }

func (d Destination) valid() bool {
	if d.Port == 0 || d.IP.IsValid() == (d.Host != "") {
		return false
	}
	if d.Host == "" {
		return true
	}
	return validHost(d.Host)
}

func validHost(h string) bool {
	if len(h) == 0 || len(h) > 255 {
		return false
	}
	for i := 0; i < len(h); i++ {
		if h[i] <= ' ' || h[i] == 0x7f {
			return false
		}
	}
	return true
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
	version := byte(StreamHeaderVersion)
	if !h.Dest.IsZero() {
		if !h.Dest.valid() || h.Dest.Port != h.TargetPort {
			return nil, ErrBadStreamHeader
		}
		version = StreamHeaderVersionExit
	}
	b := make([]byte, 0, 32)
	b = append(b, version, byte(h.Proto), byte(h.Class))
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
	if version == StreamHeaderVersionExit {
		b = appendDestination(b, h.Dest)
	}
	return b, nil
}

func appendDestination(b []byte, d Destination) []byte {
	switch ip := d.IP.Unmap(); {
	case ip.Is4():
		v := ip.As4()
		b = append(b, dstIPv4)
		b = append(b, v[:]...)
	case ip.IsValid():
		v := ip.As16()
		b = append(b, dstIPv6)
		b = append(b, v[:]...)
	default:
		b = append(b, dstDomain, byte(len(d.Host)))
		b = append(b, d.Host...)
	}
	return binary.BigEndian.AppendUint16(b, d.Port)
}

func readDestination(r io.Reader) (Destination, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return Destination{}, err
	}
	var d Destination
	switch t[0] {
	case dstIPv4, dstIPv6:
		n := 4
		if t[0] == dstIPv6 {
			n = 16
		}
		var b [16]byte
		if _, err := io.ReadFull(r, b[:n]); err != nil {
			return Destination{}, err
		}
		d.IP, _ = netip.AddrFromSlice(b[:n])
		if d.IP.Is4In6() {
			return Destination{}, ErrBadStreamHeader // encoders send these as IPv4
		}
	case dstDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Destination{}, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return Destination{}, err
		}
		d.Host = string(name)
	default:
		return Destination{}, ErrBadStreamHeader
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Destination{}, err
	}
	d.Port = binary.BigEndian.Uint16(p[:])
	if !d.valid() {
		return Destination{}, ErrBadStreamHeader
	}
	return d, nil
}

// ReadStreamHeader reads and validates a header from r.
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	var h StreamHeader
	var fixed [6]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return h, err
	}
	version := fixed[0]
	if version != StreamHeaderVersion && version != StreamHeaderVersionExit {
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
	if version == StreamHeaderVersionExit {
		d, err := readDestination(r)
		if err != nil {
			return h, err
		}
		if d.Port != h.TargetPort {
			return h, ErrBadStreamHeader
		}
		h.Dest = d
	}
	return h, nil
}
