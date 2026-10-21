// Package transport defines the plug-in contract for inter-node wire
// protocols and a registry of the transports compiled into this binary.
// A transport only moves bytes; it knows nothing about sessions or peers.
package transport

import (
	"context"
	"io"
	"net"
	"net/netip"
)

// Kind tells whether a transport yields a byte stream or datagrams.
type Kind uint8

const (
	// Stream transports deliver reliable, ordered bytes.
	Stream Kind = 1
	// Datagram transports deliver unreliable messages.
	Datagram Kind = 2
)

// Endpoint is one dialable address of a peer.
type Endpoint struct {
	Addr    netip.AddrPort
	Options map[string]any
}

// ListenConfig describes one inter-node listener.
type ListenConfig struct {
	Addr    netip.AddrPort
	Options map[string]any
}

// Transport is implemented by every wire protocol plug-in.
type Transport interface {
	Name() string
	Kind() Kind
	// Dial connects to ep. local, when valid, is the source address.
	Dial(ctx context.Context, ep Endpoint, local netip.Addr) (Conn, error)
	Listen(ctx context.Context, cfg ListenConfig) (Listener, error)
}

// Conn is a Stream-kind connection.
type Conn interface {
	io.ReadWriteCloser
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// Datagrammer is implemented by a Conn that can also carry unreliable
// datagrams beside its stream (QUIC, RFC 9221). Session v2 moves a path's
// records to datagrams when DatagramsEnabled is true; both ends of the
// connection see the same value (ADR-0014).
type Datagrammer interface {
	DatagramsEnabled() bool
	// MaxDatagramSize is the largest datagram SendDatagram accepts for
	// the life of the connection.
	MaxDatagramSize() int
	SendDatagram(b []byte) error
	// ReceiveDatagram returns the next datagram; the caller owns it.
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

// DatagramOnly is implemented by a Conn whose stream only carries the
// handshake (udp): session v1, which needs a byte stream, refuses it.
type DatagramOnly interface{ DatagramOnly() }

// Unpaced is implemented by a Datagrammer that neither paces nor
// congestion-controls its datagrams (udp, unlike QUIC): session v2 paces
// it (ADR-0016).
type Unpaced interface{ Unpaced() }

// PacketConn is a Datagram-kind connection.
type PacketConn interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) error
	Close() error
}

// Listener accepts inbound Stream-kind connections.
type Listener interface {
	Accept() (Conn, error)
	Close() error
	Addr() net.Addr
}
