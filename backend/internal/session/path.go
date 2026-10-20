package session

import (
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/frame"
)

// PathMeta says where a path runs; it is reported, never interpreted.
type PathMeta struct {
	Transport string
	Local     string
	Remote    string
}

func (m PathMeta) String() string { return m.Transport + " " + m.Local + "->" + m.Remote }

// PathInfo describes one path of a session for status, logs and the
// controller. In v1 Active marks the one active path; in v2, which uses
// every path, it marks the first-ranked one. The fields after Registered
// are set by v2 only.
type PathInfo struct {
	ID         uint64
	Meta       PathMeta
	Active     bool
	RTT        time.Duration
	LastRecv   time.Time
	BytesSent  uint64
	BytesRecv  uint64
	Registered time.Time

	RTTVar      time.Duration
	Datagram    bool // records travel in datagrams (FEC applies)
	Suspect     bool // probe timeout: takes no new data until acknowledged
	Draining    bool // being retired after a rotation
	PacketsSent uint64
	PacketsLost uint64
	Recovered   uint64 // packets rebuilt by FEC
	// PacketsRecv counts packets that arrived; RecvSpan is how many packet
	// numbers the peer used. Their gap is the raw loss of the incoming
	// direction, before FEC.
	PacketsRecv uint64
	RecvSpan    uint64
	Loss        float64 // smoothed fraction of packets lost
	Cwnd        int
	InFlight    int
}

// ctrlQueue bounds control writes waiting for a path. Only PONGs arrive at
// any rate, so a full queue means the path has stopped draining.
const ctrlQueue = 16

// path is one live, handshaken link of a session.
//
// Writes on a path come from two goroutines only: the conn's send loop
// (DATA, ACK) and the path's control loop (everything else). Its reader
// never writes. If readers wrote, two full pipes could deadlock: each
// side's reader blocked in a write, waiting for the other side's reader.
type path struct {
	id      uint64
	meta    PathMeta
	conn    *frame.Conn
	created time.Time

	ctrl     chan func() error // run by the control loop
	gone     chan struct{}     // closed when the path is removed
	goneOnce sync.Once

	dead      atomic.Bool
	lastRecv  atomic.Int64 // unix nanoseconds
	rttNs     atomic.Int64 // EWMA, 0 = unknown
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	pingSeq   uint32 // owned by the prober goroutine
}

func newPath(id uint64, meta PathMeta, conn *frame.Conn, now time.Time) *path {
	p := &path{id: id, meta: meta, conn: conn, created: now,
		ctrl: make(chan func() error, ctrlQueue), gone: make(chan struct{})}
	p.lastRecv.Store(now.UnixNano())
	return p
}

// markGone stops the path's control loop.
func (p *path) markGone() { p.goneOnce.Do(func() { close(p.gone) }) }

// observeRTT folds one sample into the EWMA (alpha = 1/8, as TCP's SRTT).
func (p *path) observeRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	old := p.rttNs.Load()
	if old == 0 {
		p.rttNs.Store(int64(sample))
		return
	}
	p.rttNs.Store(old + (int64(sample)-old)/8)
}

// rank orders standby candidates: lower is better; unknown RTT goes last.
func (p *path) rank() int64 {
	if r := p.rttNs.Load(); r > 0 {
		return r
	}
	return int64(time.Hour)
}

func (p *path) info(active bool) PathInfo {
	return PathInfo{
		ID:         p.id,
		Meta:       p.meta,
		Active:     active,
		RTT:        time.Duration(p.rttNs.Load()),
		LastRecv:   time.Unix(0, p.lastRecv.Load()),
		BytesSent:  p.bytesSent.Load(),
		BytesRecv:  p.bytesRecv.Load(),
		Registered: p.created,
	}
}
