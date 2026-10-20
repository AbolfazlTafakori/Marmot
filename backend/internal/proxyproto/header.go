// Package proxyproto encodes and decodes PROXY protocol v2 headers
// (HAProxy "The PROXY protocol", section 2.2), which carry the real client
// address to a panel inbound so its IP limits keep working.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"marmot/internal/core"
)

// Signature starts every v2 header.
var Signature = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// Command is the low nibble of the version/command byte.
type Command uint8

const (
	// CmdLocal marks a connection made by the proxy itself (health check);
	// the receiver uses the real connection addresses.
	CmdLocal Command = 0x0
	// CmdProxy marks a relayed connection with the addresses below.
	CmdProxy Command = 0x1
)

const (
	version2   = 0x20
	fixedSize  = 16
	addrSize4  = 12
	addrSize6  = 36
	famUnspec  = 0x00
	famInet    = 0x10
	famInet6   = 0x20
	protoUnspc = 0x00
	protoStrm  = 0x01
	protoDgram = 0x02
)

// Errors returned by ReadHeader.
var (
	ErrNoSignature = errors.New("proxyproto: no v2 signature")
	ErrBadHeader   = errors.New("proxyproto: malformed header")
)

// Header is a decoded PROXY v2 header. For CmdLocal the addresses are zero.
type Header struct {
	Command Command
	Proto   core.Proto
	Src     netip.AddrPort
	Dst     netip.AddrPort
}

// Append encodes h. Mixed address families are encoded as IPv6, with the
// IPv4 address mapped, as the specification requires.
func (h Header) Append(b []byte) ([]byte, error) {
	b = append(b, Signature[:]...)
	if h.Command == CmdLocal {
		b = append(b, version2|byte(CmdLocal), famUnspec|protoUnspc)
		return binary.BigEndian.AppendUint16(b, 0), nil
	}
	if h.Command != CmdProxy || !h.Proto.Valid() || !h.Src.IsValid() || !h.Dst.IsValid() {
		return nil, ErrBadHeader
	}
	src, dst := h.Src.Addr().Unmap(), h.Dst.Addr().Unmap()
	proto := byte(protoStrm)
	if h.Proto == core.ProtoUDP {
		proto = protoDgram
	}
	b = append(b, version2|byte(CmdProxy))
	if src.Is4() && dst.Is4() {
		b = append(b, famInet|proto)
		b = binary.BigEndian.AppendUint16(b, addrSize4)
		s, d := src.As4(), dst.As4()
		b = append(b, s[:]...)
		b = append(b, d[:]...)
	} else {
		b = append(b, famInet6|proto)
		b = binary.BigEndian.AppendUint16(b, addrSize6)
		s, d := src.As16(), dst.As16()
		b = append(b, s[:]...)
		b = append(b, d[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, h.Src.Port())
	return binary.BigEndian.AppendUint16(b, h.Dst.Port()), nil
}

// ReadHeader reads exactly one v2 header from r, never more, so the bytes
// that follow stay in r. TLVs are skipped.
func ReadHeader(r io.Reader) (Header, error) {
	var fixed [fixedSize]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Header{}, err
	}
	if !bytes.Equal(fixed[:12], Signature[:]) {
		return Header{}, ErrNoSignature
	}
	verCmd, famProto := fixed[12], fixed[13]
	n := int(binary.BigEndian.Uint16(fixed[14:]))
	if verCmd&0xF0 != version2 {
		return Header{}, ErrBadHeader
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Header{}, err
	}
	switch Command(verCmd & 0x0F) {
	case CmdLocal:
		return Header{Command: CmdLocal}, nil
	case CmdProxy:
	default:
		return Header{}, ErrBadHeader
	}
	h := Header{Command: CmdProxy}
	switch famProto & 0x0F {
	case protoStrm:
		h.Proto = core.ProtoTCP
	case protoDgram:
		h.Proto = core.ProtoUDP
	default:
		return Header{}, ErrBadHeader
	}
	var ipLen int
	switch famProto & 0xF0 {
	case famInet:
		ipLen = 4
	case famInet6:
		ipLen = 16
	default:
		return Header{}, ErrBadHeader
	}
	if n < 2*ipLen+4 {
		return Header{}, ErrBadHeader
	}
	src, _ := netip.AddrFromSlice(body[:ipLen])
	dst, _ := netip.AddrFromSlice(body[ipLen : 2*ipLen])
	ports := body[2*ipLen:]
	h.Src = netip.AddrPortFrom(src, binary.BigEndian.Uint16(ports))
	h.Dst = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(ports[2:]))
	return h, nil
}
