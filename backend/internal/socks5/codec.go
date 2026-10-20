// Package socks5 is the local SOCKS5 inbound of exit mode (RFC 1928): a
// panel on this node points its outbound at it, and each connection or
// UDP flow is carried to a peer that delivers it to its destination.
// Only the "no authentication" method is offered; the listener is bound
// to loopback by default.
package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strconv"
)

// Protocol constants (RFC 1928).
const (
	version5 = 0x05

	methodNoAuth       = 0x00
	methodNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Reply codes (RFC 1928 §6).
const (
	RepSucceeded           byte = 0x00
	RepGeneralFailure      byte = 0x01
	RepNotAllowed          byte = 0x02
	RepNetworkUnreachable  byte = 0x03
	RepHostUnreachable     byte = 0x04
	RepConnectionRefused   byte = 0x05
	RepCommandNotSupported byte = 0x07
	RepAddrNotSupported    byte = 0x08
)

// Errors returned by the codec.
var (
	ErrVersion     = errors.New("socks5: not a SOCKS5 message")
	ErrNoMethod    = errors.New("socks5: client offers no acceptable method")
	ErrBadAddress  = errors.New("socks5: malformed address")
	ErrAddrType    = errors.New("socks5: unsupported address type")
	ErrFragmented  = errors.New("socks5: fragmented UDP datagrams are not supported")
	ErrShortPacket = errors.New("socks5: UDP datagram too short")
)

// Addr is a SOCKS destination: an IP address or a domain name, and a port.
type Addr struct {
	IP   netip.Addr // valid for IPv4/IPv6 destinations
	Host string     // set for domain destinations
	Port uint16
}

// String formats the address for dialing ("host:port", IPv6 in brackets).
func (a Addr) String() string {
	host := a.Host
	if a.IP.IsValid() {
		host = a.IP.String()
		if a.IP.Is6() {
			host = "[" + host + "]"
		}
	}
	return host + ":" + strconv.Itoa(int(a.Port))
}

// readAddr reads ATYP | DST.ADDR | DST.PORT.
func readAddr(r io.Reader) (Addr, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return Addr{}, err
	}
	var a Addr
	switch t[0] {
	case atypIPv4, atypIPv6:
		n := 4
		if t[0] == atypIPv6 {
			n = 16
		}
		var b [16]byte
		if _, err := io.ReadFull(r, b[:n]); err != nil {
			return Addr{}, err
		}
		a.IP, _ = netip.AddrFromSlice(b[:n])
		a.IP = a.IP.Unmap()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		if l[0] == 0 {
			return Addr{}, ErrBadAddress
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return Addr{}, err
		}
		for _, c := range name {
			if c <= ' ' || c == 0x7f {
				return Addr{}, ErrBadAddress
			}
		}
		a.Host = string(name)
	default:
		return Addr{}, ErrAddrType
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Addr{}, err
	}
	a.Port = binary.BigEndian.Uint16(p[:])
	return a, nil
}

// appendAddr encodes ATYP | ADDR | PORT.
func appendAddr(b []byte, a Addr) []byte {
	switch {
	case a.IP.Is4():
		v := a.IP.As4()
		b = append(b, atypIPv4)
		b = append(b, v[:]...)
	case a.IP.IsValid():
		v := a.IP.As16()
		b = append(b, atypIPv6)
		b = append(b, v[:]...)
	default:
		b = append(b, atypDomain, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port)
}

// negotiate reads the client greeting and answers it. It returns
// ErrNoMethod (after telling the client) if "no authentication" is not
// among the offered methods.
func negotiate(rw io.ReadWriter) error {
	var h [2]byte
	if _, err := io.ReadFull(rw, h[:]); err != nil {
		return err
	}
	if h[0] != version5 || h[1] == 0 {
		return ErrVersion
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == methodNoAuth {
			_, err := rw.Write([]byte{version5, methodNoAuth})
			return err
		}
	}
	_, _ = rw.Write([]byte{version5, methodNoAcceptable})
	return ErrNoMethod
}

// request is a parsed SOCKS request.
type request struct {
	cmd byte
	dst Addr
}

// readRequest reads VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT.
func readRequest(r io.Reader) (request, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return request{}, err
	}
	if h[0] != version5 {
		return request{}, ErrVersion
	}
	dst, err := readAddr(r)
	if err != nil {
		return request{cmd: h[1]}, err
	}
	return request{cmd: h[1], dst: dst}, nil
}

// writeReply sends VER | REP | RSV | ATYP | BND.ADDR | BND.PORT.
func writeReply(w io.Writer, rep byte, bound Addr) error {
	if !bound.IP.IsValid() && bound.Host == "" {
		bound.IP = netip.IPv4Unspecified()
	}
	b := appendAddr([]byte{version5, rep, 0x00}, bound)
	_, err := w.Write(b)
	return err
}

// parseUDP splits a SOCKS UDP datagram (RSV | FRAG | ATYP | DST | DATA).
func parseUDP(pkt []byte) (Addr, []byte, error) {
	if len(pkt) < 4 {
		return Addr{}, nil, ErrShortPacket
	}
	if pkt[2] != 0 {
		return Addr{}, nil, ErrFragmented
	}
	r := &sliceReader{b: pkt[3:]}
	dst, err := readAddr(r)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return Addr{}, nil, ErrShortPacket
		}
		return Addr{}, nil, err
	}
	return dst, r.b, nil
}

// appendUDP builds a SOCKS UDP datagram header for src followed by data.
func appendUDP(b []byte, src Addr, data []byte) []byte {
	b = append(b, 0, 0, 0)
	b = appendAddr(b, src)
	return append(b, data...)
}

// sliceReader reads from a byte slice, leaving the rest in b.
type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}
