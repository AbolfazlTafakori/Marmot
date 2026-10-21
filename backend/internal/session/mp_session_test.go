package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/transport"
)

// v2Env is a v2 session between a (initiator) and b, over paths a test
// can break.
type v2Env struct {
	ts     *testServer
	a, b   PeerSession
	faults []*chaosConn
	block  bool // a frozen path blocks writes instead of dropping them
}

// chaosConn turns into a blackhole on Freeze: reads deliver nothing, and
// writes either vanish or, like a TCP path whose send buffer filled up,
// block until the connection is closed.
type chaosConn struct {
	net.Conn
	block  bool
	frozen atomic.Bool
	closed chan struct{}
	once   sync.Once
}

func (c *chaosConn) Freeze() { c.frozen.Store(true) }

func (c *chaosConn) Read(b []byte) (int, error) {
	for {
		n, err := c.Conn.Read(b)
		if err != nil || !c.frozen.Load() {
			return n, err
		}
	}
}

func (c *chaosConn) Write(b []byte) (int, error) {
	if c.frozen.Load() {
		if c.block {
			<-c.closed
			return 0, net.ErrClosed
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *chaosConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// newV2 dials a v2 session over n TCP paths; path i claims remote
// 10.0.0.i so that paths count as different peer addresses.
func newV2(t testing.TB, n int, block bool) *v2Env {
	t.Helper()
	e := &v2Env{ts: startServer(t, map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()}, 2), block: block}
	conn := e.faulty(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := Dial(ctx, DialConfig{Local: idA, LocalID: "a", Peer: "b", PeerKey: idB.PublicKey(),
		Caps: e.ts.caps, Conn: testConnConfig(Initiator)}, conn, metaN(0))
	if err != nil {
		t.Fatal(err)
	}
	e.a = a
	e.b = e.ts.next(t)
	t.Cleanup(func() { _ = e.a.Close(); _ = e.b.Close() })
	for i := 1; i < n; i++ {
		if err := e.a.Join(ctx, e.faulty(t), metaN(i), false); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return len(e.b.Stats().Paths) == n })
	return e
}

func metaN(i int) PathMeta {
	return PathMeta{Transport: "tcp", Local: "a", Remote: fmt.Sprintf("10.0.0.%d:9443", i)}
}

func (e *v2Env) faulty(t testing.TB) *chaosConn {
	c := &chaosConn{Conn: e.ts.dialRaw(t).(net.Conn), block: e.block, closed: make(chan struct{})}
	e.faults = append(e.faults, c)
	return c
}

// echo answers every stream b accepts and copies it back.
func echo(s PeerSession) {
	go func() {
		for {
			st, _, err := s.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer st.Close()
				_, _ = st.Write([]byte{frame.ReplyOK})
				_, _ = io.Copy(st, st)
			}()
		}
	}()
}

// roundTrip sends size random bytes on a new stream and checks the echo.
func roundTrip(t *testing.T, s PeerSession, h frame.StreamHeader, size int, seed uint64) error {
	st, err := s.OpenStream(context.Background(), h)
	if err != nil {
		return err
	}
	defer st.Close()
	rng := rand.New(rand.NewPCG(seed, seed+1))
	want := sha256.New()
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 32<<10)
		for sent := 0; sent < size; {
			n := min(len(buf), size-sent)
			for i := range buf[:n] {
				buf[i] = byte(rng.Uint32())
			}
			want.Write(buf[:n])
			if _, err := st.Write(buf[:n]); err != nil {
				errc <- err
				return
			}
			sent += n
		}
		errc <- nil
	}()
	got := sha256.New()
	if _, err := io.CopyN(got, st, int64(size)); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if err := <-errc; err != nil {
		return err
	}
	if !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
		return errors.New("echo differs from what was sent")
	}
	return nil
}

func TestV2ManyStreamsAndRotation(t *testing.T) {
	e := newV2(t, 2, false)
	echo(e.b)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- roundTrip(t, e.a, testHeader, 2<<20, uint64(i))
		}()
	}
	// Rotate twice while the streams run: no byte may be lost.
	for range 2 {
		time.Sleep(50 * time.Millisecond)
		if err := e.a.Join(context.Background(), e.faulty(t), metaN(len(e.faults)), true); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return len(e.a.Stats().Paths) == 2 && len(e.b.Stats().Paths) == 2 })
	waitFor(t, func() bool { return e.a.NumStreams() == 0 && e.b.NumStreams() == 0 })
}

// TestV2BlackholeNoStall is the point of v2: a silently dropped path costs
// about one probe timeout, not the watchdog plus a resend round trip.
func TestV2BlackholeNoStall(t *testing.T) {
	t.Run("writes vanish", func(t *testing.T) { testV2BlackholeNoStall(t, false) })
	t.Run("writes block", func(t *testing.T) { testV2BlackholeNoStall(t, true) })
}

func testV2BlackholeNoStall(t *testing.T, block bool) {
	e := newV2(t, 3, block)
	echo(e.b)
	st, err := e.a.OpenStream(context.Background(), testHeader)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var stop atomic.Bool
	go func() {
		chunk := make([]byte, 8<<10)
		for i := 0; !stop.Load(); i++ {
			for j := range chunk {
				chunk[j] = byte(i + j)
			}
			if _, err := st.Write(chunk); err != nil {
				return
			}
		}
	}()
	var maxGap time.Duration
	last := time.Now()

	buf := make([]byte, 8<<10)
	deadline := time.Now().Add(1500 * time.Millisecond)
	froze := 0
	for i := 0; time.Now().Before(deadline); i++ {
		if _, err := io.ReadFull(st, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		for j := range buf {
			if buf[j] != byte(i+j) {
				t.Fatalf("chunk %d byte %d corrupt", i, j)
			}
		}
		now := time.Now()
		maxGap = max(maxGap, now.Sub(last))
		last = now
		if froze < 2 && now.After(deadline.Add(-time.Duration(1000-froze*400)*time.Millisecond)) {
			e.faults[froze].Freeze()
			froze++
		}
	}
	stop.Store(true)
	if froze != 2 {
		t.Fatalf("froze %d paths", froze)
	}
	if maxGap > 600*time.Millisecond {
		t.Fatalf("longest stall %v with paths blackholed", maxGap)
	}
	t.Logf("longest stall %v", maxGap)
	waitFor(t, func() bool { return len(e.a.Stats().Paths) == 1 })
}

func TestV2ClosedStreamsDoNotLeakWindow(t *testing.T) {
	e := newV2(t, 1, false)
	// The receiver reads a little of each stream and closes it, so most of
	// what was sent is discarded; the session window must come back.
	const streams = 40 // 40 MiB offered: more than twice the session window
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for range streams {
			st, _, err := e.b.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				_, _ = st.Write([]byte{frame.ReplyOK})
				_, _ = io.ReadFull(st, make([]byte, 10))
				_ = st.Close()
			}()
		}
	}()
	big := make([]byte, 1<<20)
	for range streams {
		st, err := e.a.OpenStream(context.Background(), testHeader)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = st.Write(big)
		_, _ = st.Read(make([]byte, 1))
		_ = st.Close()
	}
	<-accepted
	waitFor(t, func() bool { return e.a.NumStreams() == 0 && e.b.NumStreams() == 0 })
	echo(e.b)
	if err := roundTrip(t, e.a, testHeader, 24<<20, 9); err != nil {
		t.Fatalf("after closed streams: %v", err)
	}
}

func TestV2VIPDuplicated(t *testing.T) {
	e := newV2(t, 2, false)
	echo(e.b)
	before := pathBytes(e.a)
	vip := testHeader
	vip.Class = core.ClassVIP
	if err := roundTrip(t, e.a, vip, 256<<10, 3); err != nil {
		t.Fatal(err)
	}
	after := pathBytes(e.a)
	// A copy whose original was acknowledged first is skipped, and on
	// loopback acknowledgements are quick; most bytes must still go twice.
	for id, b := range after {
		if b-before[id] < 128<<10 {
			t.Fatalf("path %x carried %d bytes of a 256 KiB VIP stream; both paths should", id, b-before[id])
		}
	}
}

func pathBytes(s PeerSession) map[uint64]uint64 {
	m := map[uint64]uint64{}
	for _, p := range s.Stats().Paths {
		m[p.ID] = p.BytesSent
	}
	return m
}

func TestV2ResumeTimeout(t *testing.T) {
	e := newV2(t, 1, false)
	e.faults[0].Freeze()
	select {
	case <-e.a.Done():
	case <-time.After(6 * time.Second):
		t.Fatal("session outlived its only path by more than the resume timeout")
	}
	if !errors.Is(e.a.Err(), ErrResumeTimeout) {
		t.Fatalf("err %v", e.a.Err())
	}
}

// dgPair is an in-memory QUIC stand-in: a stream for the handshake and a
// lossy datagram channel each way.
type dgConn struct {
	net.Conn
	in, out chan []byte
	loss    *atomic.Uint64 // per mille
	closed  chan struct{}
	once    *sync.Once
}

func dgPair(lossPerMille uint64) (*dgConn, *dgConn) {
	ca, cb := net.Pipe()
	ab, ba := make(chan []byte, 4096), make(chan []byte, 4096)
	loss := &atomic.Uint64{}
	loss.Store(lossPerMille)
	closed, once := make(chan struct{}), &sync.Once{}
	return &dgConn{Conn: ca, in: ba, out: ab, loss: loss, closed: closed, once: once},
		&dgConn{Conn: cb, in: ab, out: ba, loss: loss, closed: closed, once: once}
}

func (c *dgConn) DatagramsEnabled() bool { return true }
func (c *dgConn) MaxDatagramSize() int   { return 1200 }

func (c *dgConn) SendDatagram(b []byte) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	if len(b) > c.MaxDatagramSize() {
		return errors.New("datagram too large")
	}
	if rand.Uint64N(1000) < c.loss.Load() {
		return nil
	}
	select {
	case c.out <- append([]byte(nil), b...):
	default: // a full queue drops, as UDP does
	}
	return nil
}

func (c *dgConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case d := <-c.in:
		return d, nil
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *dgConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

var _ transport.Datagrammer = (*dgConn)(nil)

// newV2Datagram builds a v2 session over n lossy datagram paths.
func newV2Datagram(t *testing.T, n int, lossPerMille uint64, fecData, fecParity int) (PeerSession, PeerSession) {
	t.Helper()
	keys, _ := NewPeerKeys(map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()})
	sessions := make(chan PeerSession, 1)
	bcfg := testConnConfig(Responder)
	bcfg.FECData, bcfg.FECParity = fecData, fecParity
	acc, err := NewAcceptor(AcceptorConfig{Local: idB, Peers: keys, Caps: versionCaps[2], Conn: bcfg,
		OnSession: func(s PeerSession) { sessions <- s }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acc.Close() })
	acfg := testConnConfig(Initiator)
	acfg.FECData, acfg.FECParity = fecData, fecParity
	var a PeerSession
	for i := range n {
		ca, cb := dgPair(lossPerMille)
		go func() { _ = acc.Handle(context.Background(), cb, PathMeta{Transport: "quic"}) }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		meta := PathMeta{Transport: "quic", Remote: fmt.Sprintf("10.1.0.%d:443", i)}
		if i == 0 {
			a, err = Dial(ctx, DialConfig{Local: idA, LocalID: "a", Peer: "b", PeerKey: idB.PublicKey(),
				Caps: versionCaps[2], Conn: acfg}, ca, meta)
		} else {
			err = a.Join(ctx, ca, meta, false)
		}
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	b := <-sessions
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	waitFor(t, func() bool { return len(b.Stats().Paths) == n })
	for _, p := range a.Stats().Paths {
		if !p.Datagram {
			t.Fatal("path is not a datagram path")
		}
	}
	return a, b
}

func TestV2DatagramLossRetransmits(t *testing.T) {
	a, b := newV2Datagram(t, 2, 80, 0, 0)
	echo(b)
	if err := roundTrip(t, a, testHeader, 2<<20, 5); err != nil {
		t.Fatal(err)
	}
	var lost uint64
	for _, p := range a.Stats().Paths {
		lost += p.PacketsLost
	}
	if lost == 0 {
		t.Fatal("8 % loss and no packet counted lost")
	}
}

func TestV2DatagramFECRecovers(t *testing.T) {
	a, b := newV2Datagram(t, 2, 30, 4, 2)
	echo(b)
	if err := roundTrip(t, a, testHeader, 2<<20, 6); err != nil {
		t.Fatal(err)
	}
	var recovered uint64
	for _, s := range []PeerSession{a, b} {
		for _, p := range s.Stats().Paths {
			recovered += p.Recovered
		}
	}
	if recovered == 0 {
		t.Fatal("FEC rebuilt no packet at 3 % loss")
	}
	t.Logf("packets rebuilt by FEC: %d", recovered)
}

func TestV2TuneRanksAndFEC(t *testing.T) {
	a, b := newV2Datagram(t, 2, 0, 4, 0)
	echo(b)
	paths := a.Stats().Paths
	last := paths[len(paths)-1].ID
	a.Tune(Tuning{Ranks: map[uint64]int{last: 0}, FECData: 4, FECParity: 1})
	if got := a.Stats().Paths[0].ID; got != last {
		t.Fatalf("first path %x, want ranked %x", got, last)
	}
	if err := roundTrip(t, a, testHeader, 256<<10, 7); err != nil {
		t.Fatal(err)
	}
	mp := a.(*MPSession)
	mp.mu.Lock()
	enabled := mp.fecEnc.Enabled()
	mp.mu.Unlock()
	if !enabled {
		t.Fatal("Tune did not turn FEC on")
	}
}

func TestV2CloseSemantics(t *testing.T) {
	e := newV2(t, 1, false)
	got := make(chan []byte, 1)
	peerWrite := make(chan error, 1)
	go func() {
		st, _, err := e.b.AcceptStream(context.Background())
		if err != nil {
			return
		}
		_, _ = st.Write([]byte{frame.ReplyOK})
		data, _ := io.ReadAll(st) // until the opener's FIN
		got <- data
		// The opener closed both directions: its STOP makes our writes fail.
		var err2 error
		for range 100 {
			if _, err2 = st.Write(make([]byte, 1024)); err2 != nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		peerWrite <- err2
	}()
	st, err := e.a.OpenStream(context.Background(), testHeader)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("marmot"), 50000)
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = st.Close() // data already written must still arrive, then EOF
	if d := <-got; !bytes.Equal(d, payload) {
		t.Fatalf("peer read %d bytes, want %d", len(d), len(payload))
	}
	if err := <-peerWrite; !errors.Is(err, ErrStreamStopped) {
		t.Fatalf("peer write after close: %v", err)
	}
	if _, err := st.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("write after close succeeded")
	}
	waitFor(t, func() bool { return e.a.NumStreams() == 0 && e.b.NumStreams() == 0 })
}

func TestV2Deadlines(t *testing.T) {
	e := newV2(t, 1, false)
	go func() {
		st, _, err := e.b.AcceptStream(context.Background())
		if err == nil {
			_, _ = st.Write([]byte{frame.ReplyOK})
		}
	}()
	st, err := e.a.OpenStream(context.Background(), testHeader)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.(interface{ AwaitReply(context.Context) error }).AwaitReply(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = st.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	if _, err := st.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past deadline: %v", err)
	}
	if d := time.Since(start); d < 40*time.Millisecond || d > time.Second {
		t.Fatalf("deadline fired after %v", d)
	}
	_ = st.SetReadDeadline(time.Time{})
	// A write that cannot drain (the peer never reads) hits its deadline.
	_ = st.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	big := make([]byte, 64<<20)
	if _, err := st.Write(big); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write past deadline: %v", err)
	}
}

func BenchmarkV2Throughput(b *testing.B) {
	for _, n := range []int{1, 2} {
		b.Run(fmt.Sprintf("paths=%d", n), func(b *testing.B) {
			e := newV2(b, n, false)
			go func() {
				st, _, err := e.b.AcceptStream(context.Background())
				if err != nil {
					return
				}
				_, _ = st.Write([]byte{frame.ReplyOK})
				_, _ = io.Copy(io.Discard, st)
			}()
			st, err := e.a.OpenStream(context.Background(), testHeader)
			if err != nil {
				b.Fatal(err)
			}
			buf := make([]byte, 64<<10)
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := st.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// With every path suspect, data goes to one the peer still reaches, not
// the best ranked or the last acknowledged: a busy fast path that just
// died has both.
func TestBestSuspectStillReceives(t *testing.T) {
	now := time.Now()
	// The dead path carried everything until 100 ms ago; the lossy idle
	// one has heard from its peer since turning suspect.
	dead := &mpPath{id: 1, suspect: true, suspectAt: now.Add(-90 * time.Millisecond),
		lastRecv: now.Add(-100 * time.Millisecond), lastProgress: now.Add(-100 * time.Millisecond)}
	lossy := &mpPath{id: 2, suspect: true, suspectAt: now.Add(-80 * time.Millisecond),
		lastRecv: now.Add(-20 * time.Millisecond), lastProgress: now.Add(-2 * time.Second)}
	s := &MPSession{order: []*mpPath{dead, lossy}}
	if got := s.bestSuspectLocked(); got != lossy {
		t.Fatalf("picked path %d, want the one that still receives", got.id)
	}
	if !s.eligibleNewLocked(lossy) || s.eligibleNewLocked(dead) {
		t.Fatal("new data must go to the recently acknowledged suspect only")
	}
	healthy := &mpPath{id: 3}
	s.order = append([]*mpPath{healthy}, s.order...)
	if s.bestSuspectLocked() != nil {
		t.Fatal("a suspect path chosen while a healthy one exists")
	}
}
