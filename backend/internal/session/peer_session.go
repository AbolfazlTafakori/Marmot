package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/transport"
)

// PeerSession is what the node sees of a session with a peer. Both
// versions implement it: v1 (*MuxSession) and v2 (*MPSession).
type PeerSession interface {
	Session
	ID() crypto.SessionID
	Peer() core.NodeID
	PeerKey() ed25519.PublicKey
	Role() Role
	Caps() uint32
	Version() int
	Started() time.Time
	Done() <-chan struct{}
	Err() error
	Stats() ConnStats
	NumStreams() int
	// Join adds a path (initiator only). With rotate the new path replaces
	// the active (v1) or first-ranked (v2) path make-before-break.
	Join(ctx context.Context, conn transport.Conn, meta PathMeta, rotate bool) error
	// Tune applies the controller's decisions. v1 has nothing to tune.
	Tune(Tuning)
}

// Tuning is what the adaptive controller sets on a session (ADR-0015).
type Tuning struct {
	// Ranks orders paths by id, lower first. Paths without a rank come
	// after ranked ones, in the session's own order.
	Ranks map[uint64]int
	// FECData and FECParity set the FEC group for datagram paths; parity 0
	// turns FEC off.
	FECData, FECParity int
}

// acceptedSession is what the acceptor needs on top of PeerSession.
type acceptedSession interface {
	PeerSession
	// addInbound attaches a path the peer joined.
	addInbound(conn transport.Conn, keys crypto.CipherPair, meta PathMeta) error
	// revoke closes the session because the peer's key was removed.
	revoke()
}

// recordConn is the record layer of one path: frame.Conn on stream paths,
// frame.DatagramConn on datagram paths.
type recordConn interface {
	WriteRecord(t frame.Type, body []byte, pad int) error
	ReadRecord() (frame.Type, []byte, error)
	Close() error
}

// errNeedsV2 means a datagram-only path (udp) was offered to session v1,
// which needs a byte stream (ADR-0016).
var errNeedsV2 = errors.New("session: this transport carries session v2 only")

// streamCapable reports whether conn can carry session v1.
func streamCapable(conn transport.Conn) bool {
	_, only := conn.(transport.DatagramOnly)
	return !only
}

// datagramPath reports whether a v2 path over conn carries its records in
// datagrams: both QUIC ends then negotiated datagram support, so both
// sides of the path reach the same answer (ADR-0014).
func datagramPath(conn transport.Conn) (transport.Datagrammer, bool) {
	d, ok := conn.(transport.Datagrammer)
	if !ok || !d.DatagramsEnabled() {
		return nil, false
	}
	return d, true
}

// newPathConn builds the record layer of a v2 path and returns it with
// the largest record body it carries.
func newPathConn(conn transport.Conn, keys crypto.CipherPair) (recordConn, bool, int) {
	if d, ok := datagramPath(conn); ok {
		dc := frame.NewDatagramConn(datagramIO{d: d, conn: conn}, keys, d.MaxDatagramSize())
		maxBody := dc.MaxBody()
		return dc, true, maxBody
	}
	return frame.NewConn(conn, keys), false, frame.MaxBody
}

// datagramIO adapts a Datagrammer to frame.PacketIO.
type datagramIO struct {
	d    transport.Datagrammer
	conn transport.Conn
}

func (a datagramIO) WritePacket(b []byte) error { return a.d.SendDatagram(b) }

func (a datagramIO) ReadPacket(b []byte) (int, error) {
	p, err := a.d.ReceiveDatagram(context.Background())
	if err != nil {
		return 0, err
	}
	return copy(b, p), nil
}

func (a datagramIO) Close() error { return a.conn.Close() }
