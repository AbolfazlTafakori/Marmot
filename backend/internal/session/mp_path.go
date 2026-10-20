package session

import (
	"cmp"
	"slices"
	"time"
)

// relayTransport is the PathMeta.Transport of a relayed path; it matches
// mesh.TransportRelay.
const relayTransport = "relay"

// Congestion and timing constants of v2 (ADR-0013 §6, spec §11.4).
// A stream path acknowledges every 8th packet: TCP loses nothing inside a
// live connection, so acknowledging more often only costs writes. A
// datagram path acknowledges every 2nd, as RFC 9002 does.
const (
	ackEveryStream   = 8
	ackEveryDatagram = 2
	initialRTT       = 300 * time.Millisecond
	maxAckDelay      = 25 * time.Millisecond
	initialCwnd      = 1 << 20
	minCwnd          = 256 << 10
	maxCwnd          = 32 << 20
	rateWindow       = 5 * time.Second
	lossFactorMin    = 0.25
	maxPTOBackoff    = 6
	maxRecvRanges    = 256
)

// frameKind says what a sent frame was, so that its loss or
// acknowledgement can be handled.
type frameKind uint8

const (
	fkStream frameKind = iota + 1
	fkMaxData
	fkMaxStreamData
	fkReset
	fkStop
)

// sentFrame is the part of a sent packet that matters after sending.
type sentFrame struct {
	kind frameKind
	sid  uint32
	off  uint64
	n    int
	fin  bool
}

// sentPacket is one packet in flight on a path.
type sentPacket struct {
	pn           uint64
	at           time.Time
	size         int
	ackEliciting bool
	acked, lost  bool
	requeued     bool // its frames were already queued again after a PTO
	delivered    int64
	deliveredAt  time.Time
	frames       []sentFrame
}

// rateSample is one delivery-rate measurement.
type rateSample struct {
	at   time.Time
	rate float64 // bytes per second
}

// mpPath is one path of a v2 session. Everything but the immutable
// fields and the channels is guarded by the session's mutex.
type mpPath struct {
	id       uint64
	meta     PathMeta
	conn     recordConn
	datagram bool
	relayed  bool
	maxBody  int
	created  time.Time

	wake chan struct{} // wakes the writer
	gone chan struct{} // closed when the path is removed

	dead, draining, suspect bool
	drainSince              time.Time
	order                   int // position in the session's order

	// Sending.
	nextPN       uint64
	sent         []*sentPacket // ascending pn; acked and lost ones pruned from the front
	inflight     int           // bytes of ack-eliciting packets neither acked nor lost
	elicitCount  int           // number of those packets
	cwnd         int
	largestAcked uint64
	anyAcked     bool
	ptoCount     int
	lastElicit   time.Time // last ack-eliciting packet sent
	lastProgress time.Time // last ACK that acknowledged something new
	needProbe    bool
	lossTime     time.Time // earliest time-threshold loss, zero if none
	repairQ      []repairItem
	fbuf         []byte // writer scratch for frames
	delivered    int64
	deliveredAt  time.Time
	rates        [8]rateSample
	rateIdx      int
	lossFactor   float64
	recoveryPN   uint64 // losses below this were already answered

	srtt, rttvar, minRTT, latestRTT time.Duration
	hasRTT                          bool

	// Receiving.
	recvd       rangeSet
	recvFloor   uint64 // packet numbers below are treated as seen
	largestRecv uint64
	largestAt   time.Time
	anyRecv     bool
	ackPending  int       // ack-eliciting packets since the last ACK
	ackDue      time.Time // zero: no ACK pending
	ackNow      bool
	ackStale    bool // received something not yet acknowledged
	lastRecv    time.Time

	// Counters.
	pktsSent, pktsLost, recovered uint64
	pktsRecv                      uint64 // received from the wire, not rebuilt
	bytesSent, bytesRecv          uint64
	lossEWMA                      float64
	lastSent, lastLost            uint64 // at the previous loss sample
}

func newMPPath(id uint64, meta PathMeta, conn recordConn, datagram bool, maxBody int, now time.Time) *mpPath {
	return &mpPath{
		id: id, meta: meta, conn: conn, datagram: datagram, maxBody: maxBody,
		relayed: meta.Transport == relayTransport, created: now,
		wake: make(chan struct{}, 1), gone: make(chan struct{}),
		cwnd: initialCwnd, lossFactor: 1, lastRecv: now, lastProgress: now, deliveredAt: now,
	}
}

// recvSpan is how many packet numbers the peer has used on this path, as
// far as this side has seen.
func (p *mpPath) recvSpan() uint64 {
	if !p.anyRecv {
		return 0
	}
	return p.largestRecv + 1
}

// healthy reports whether the path may take new data at all.
func (p *mpPath) healthy() bool { return !p.dead && !p.draining && !p.suspect }

// hasRoom reports whether the congestion window allows another packet.
func (p *mpPath) hasRoom() bool { return p.inflight < p.cwnd }

// pruneSent drops acknowledged and lost packets from the front.
func (p *mpPath) pruneSent(free func(*sentPacket)) {
	i := 0
	for i < len(p.sent) && (p.sent[i].acked || p.sent[i].lost) {
		free(p.sent[i])
		i++
	}
	if i > 0 {
		p.sent = slices.Delete(p.sent, 0, i)
	}
}

// pathLess orders paths for scheduling: healthy before suspect before
// draining, then the controller's rank, then direct before relayed, then
// lower RTT, then age.
func pathLess(ranks map[uint64]int) func(a, b *mpPath) int {
	return func(a, b *mpPath) int {
		if c := cmp.Compare(pathClass(a), pathClass(b)); c != 0 {
			return c
		}
		ra, oka := ranks[a.id]
		rb, okb := ranks[b.id]
		if oka != okb {
			if oka {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(ra, rb); oka && c != 0 {
			return c
		}
		if a.relayed != b.relayed {
			if a.relayed {
				return 1
			}
			return -1
		}
		if c := cmp.Compare(a.rtt(), b.rtt()); c != 0 {
			return c
		}
		return a.created.Compare(b.created)
	}
}

func pathClass(p *mpPath) int {
	switch {
	case p.draining:
		return 2
	case p.suspect:
		return 1
	}
	return 0
}

// info reports the path for status and the controller.
func (p *mpPath) info(first bool) PathInfo {
	return PathInfo{
		ID: p.id, Meta: p.meta, Active: first, RTT: p.srtt, RTTVar: p.rttvar,
		LastRecv: p.lastRecv, BytesSent: p.bytesSent, BytesRecv: p.bytesRecv, Registered: p.created,
		Datagram: p.datagram, Suspect: p.suspect, Draining: p.draining,
		PacketsSent: p.pktsSent, PacketsLost: p.pktsLost, Recovered: p.recovered,
		PacketsRecv: p.pktsRecv, RecvSpan: p.recvSpan(),
		Loss: p.lossEWMA, Cwnd: p.cwnd, InFlight: p.inflight,
	}
}
