package core

import "fmt"

// Class is the scheduling class of a user-facing port.
type Class uint8

const (
	// ClassTunneled is ordinary user traffic.
	ClassTunneled Class = 1
	// ClassVIP is control traffic of panel nodes; it is duplicated over
	// the best paths so a single path failure is never visible.
	ClassVIP Class = 2
)

func (c Class) String() string {
	switch c {
	case ClassTunneled:
		return "tunneled"
	case ClassVIP:
		return "vip"
	default:
		return fmt.Sprintf("class(%d)", uint8(c))
	}
}

// Valid reports whether c is a known class.
func (c Class) Valid() bool { return c == ClassTunneled || c == ClassVIP }

// Proto is the transport-layer protocol of a user flow.
type Proto uint8

// User flow protocols.
const (
	ProtoTCP Proto = 1
	ProtoUDP Proto = 2
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	default:
		return fmt.Sprintf("proto(%d)", uint8(p))
	}
}

// Valid reports whether p is a known protocol.
func (p Proto) Valid() bool { return p == ProtoTCP || p == ProtoUDP }

// ParseProto converts "tcp" or "udp" to a Proto.
func ParseProto(s string) (Proto, error) {
	switch s {
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	default:
		return 0, fmt.Errorf("unknown protocol %q", s)
	}
}
