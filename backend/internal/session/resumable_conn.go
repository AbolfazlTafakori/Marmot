package session

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"marmot/internal/frame"
)

// Role says which side of a session this is. Only the initiator chooses
// the active path; the responder follows its ACTIVATE records. With one
// side deciding, the two sides can never activate different paths at once.
type Role uint8

// Roles of the two sides of a session.
const (
	Initiator Role = 1
	Responder Role = 2
)

// ConnConfig configures a ResumableConn.
type ConnConfig struct {
	Role          Role
	SendBuffer    int
	ProbeInterval time.Duration
	// DeadAfter is how long a path may stay silent before it is dropped.
	DeadAfter     time.Duration
	ResumeTimeout time.Duration
	Logger        *slog.Logger
	// OnPathDown is called after a path is removed. It runs on a session
	// goroutine and must not block.
	OnPathDown func(PathInfo, error)
}

func (cfg ConnConfig) validate() error {
	switch {
	case cfg.Role != Initiator && cfg.Role != Responder:
		return fmt.Errorf("session: invalid role %d", cfg.Role)
	case cfg.SendBuffer < ackEvery:
		return fmt.Errorf("session: send buffer %d below %d", cfg.SendBuffer, ackEvery)
	case cfg.ProbeInterval <= 0 || cfg.DeadAfter <= cfg.ProbeInterval:
		return fmt.Errorf("session: need 0 < probe interval < dead-after")
	case cfg.ResumeTimeout <= 0:
		return fmt.Errorf("session: resume timeout must be positive")
	}
	return nil
}

const (
	ackEvery      = 64 << 10
	ackInterval   = 50 * time.Millisecond
	closeGrace    = time.Second
	recvInitial   = 64 << 10
	maxRecvBuffer = 256 << 20
)

// Errors reported by a ResumableConn.
var (
	ErrClosed        = errors.New("session: closed")
	ErrResumeTimeout = errors.New("session: no path became active within the resume timeout")
	ErrClosedByPeer  = errors.New("session: closed by peer")
	ErrNotInitiator  = errors.New("session: only the initiator chooses the active path")
	ErrUnknownPath   = errors.New("session: unknown path")
	errProtocol      = errors.New("session: protocol violation")
	errPathTimeout   = errors.New("session: path silent for too long")
	errPathRetired   = errors.New("session: path retired after rotation")
)

// ResumableConn turns a changing set of paths into one reliable, ordered
// byte stream per direction (docs/spec/frame.md §5). Every byte has an
// offset; unacknowledged bytes stay buffered, and when a new path becomes
// active the sender resends from the offset the receiver reports. The
// stream mux above never sees a path change.
type ResumableConn struct {
	cfg ConnConfig
	log *slog.Logger

	mu       sync.Mutex
	cond     *sync.Cond // signalled on any change readers or writers wait for
	paths    map[uint64]*path
	nextID   uint64
	active   *path
	retiring *path // previous active path, closed once the new one is ready
	epoch    uint32
	gen      uint64 // bumped on every active-path change
	ready    bool   // the active path's resend offset is known

	sbuf     *ring // bytes [ackedOff, writeOff)
	ackedOff uint64
	sentOff  uint64
	writeOff uint64

	rbuf        *ring // bytes [consumedOff, recvOff)
	consumedOff uint64
	recvOff     uint64
	ackSentOff  uint64

	closed      bool
	closeErr    error
	resumeTimer *time.Timer

	wake chan struct{}
	done chan struct{}
	wg   sync.WaitGroup
}

// NewResumableConn creates a conn with no paths. Add them with AddPath.
func NewResumableConn(cfg ConnConfig) (*ResumableConn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := &ResumableConn{
		cfg:   cfg,
		log:   log,
		paths: make(map[uint64]*path),
		sbuf:  newRing(cfg.SendBuffer, cfg.SendBuffer),
		rbuf:  newRing(recvInitial, maxRecvBuffer),
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	c.armResumeLocked()
	c.wg.Add(2)
	go c.sendLoop()
	go c.watchdog()
	return c, nil
}

// Read implements io.Reader.
func (c *ResumableConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	for c.rbuf.Len() == 0 && !c.closed {
		c.cond.Wait()
	}
	if c.rbuf.Len() == 0 {
		err := c.closeErr
		c.mu.Unlock()
		return 0, err
	}
	n := c.rbuf.Read(b)
	c.consumedOff += uint64(n)
	// ACK what has been consumed, not what has arrived: then the peer's
	// unacknowledged window bounds our receive buffer.
	due := c.consumedOff-c.ackSentOff >= ackEvery
	c.mu.Unlock()
	if due {
		c.kick()
	}
	return n, nil
}

// Write implements io.Writer. It blocks while the send buffer is full,
// which is the backpressure of the whole session.
func (c *ResumableConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for n < len(b) {
		for c.sbuf.Free() == 0 && !c.closed {
			c.cond.Wait()
		}
		if c.closed {
			return n, c.closeErr
		}
		k := c.sbuf.Write(b[n:])
		n += k
		c.writeOff += uint64(k)
		c.kick()
	}
	return n, nil
}

// Close closes the conn and all of its paths, telling the peer, and waits
// for the conn's goroutines to finish.
func (c *ResumableConn) Close() error {
	c.shutdown(ErrClosed, frame.CloseShutdown, true)
	c.wg.Wait()
	return nil
}

// Done is closed when the conn has shut down.
func (c *ResumableConn) Done() <-chan struct{} { return c.done }

// Err returns why the conn closed, or nil while it is open.
func (c *ResumableConn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

// shutdown closes the conn. It never waits for goroutines, so a session
// goroutine may call it.
func (c *ResumableConn) shutdown(err error, code uint16, notifyPeer bool) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed, c.closeErr = true, err
	if c.resumeTimer != nil {
		c.resumeTimer.Stop()
		c.resumeTimer = nil
	}
	paths := make([]*path, 0, len(c.paths))
	for _, p := range c.paths {
		p.dead.Store(true)
		p.markGone()
		paths = append(paths, p)
	}
	active, ready := c.active, c.ready
	c.paths, c.active, c.retiring = map[uint64]*path{}, nil, nil
	c.cond.Broadcast()
	c.mu.Unlock()
	close(c.done)

	closeAll := func() {
		for _, p := range paths {
			_ = p.conn.Close()
		}
	}
	if !notifyPeer || active == nil || !ready {
		closeAll()
		return
	}
	// The CLOSE write can block on a stuck path; the timer bounds it.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.AfterFunc(closeGrace, closeAll)
		defer t.Stop()
		body := frame.CloseBody{Code: code, Reason: reasonOf(err)}.Append(nil)
		_ = active.conn.WriteRecord(frame.TypeClose, body, 0)
		closeAll()
	}()
}

func reasonOf(err error) string {
	if errors.Is(err, ErrClosed) {
		return ""
	}
	return err.Error()
}

// kick wakes the send loop without blocking.
func (c *ResumableConn) kick() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// armResumeLocked starts the resume timer unless it is running. While no
// path is active and ready, the timer closes the conn when it fires.
func (c *ResumableConn) armResumeLocked() {
	if c.resumeTimer != nil || c.closed {
		return
	}
	c.resumeTimer = time.AfterFunc(c.cfg.ResumeTimeout, func() {
		c.mu.Lock()
		expired := !c.ready
		c.resumeTimer = nil
		c.mu.Unlock()
		if expired {
			c.log.Warn("session resume timeout", "timeout", c.cfg.ResumeTimeout)
			c.shutdown(ErrResumeTimeout, frame.CloseNormal, false)
		}
	})
}

func (c *ResumableConn) disarmResumeLocked() {
	if c.resumeTimer != nil {
		c.resumeTimer.Stop()
		c.resumeTimer = nil
	}
}

// ConnStats is a snapshot of a ResumableConn.
type ConnStats struct {
	Paths    []PathInfo
	Epoch    uint32
	Ready    bool
	SentOff  uint64 // bytes handed to the peer so far (resent bytes count once)
	AckedOff uint64
	RecvOff  uint64
}

// Stats returns a snapshot for status reporting.
func (c *ResumableConn) Stats() ConnStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := ConnStats{Epoch: c.epoch, Ready: c.ready, SentOff: c.writeOff, AckedOff: c.ackedOff, RecvOff: c.recvOff}
	for _, p := range c.paths {
		s.Paths = append(s.Paths, p.info(p == c.active))
	}
	return s
}

var _ io.ReadWriteCloser = (*ResumableConn)(nil)
