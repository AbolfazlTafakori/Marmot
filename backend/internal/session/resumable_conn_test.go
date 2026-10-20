package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"marmot/internal/crypto"
	"marmot/internal/frame"
)

var (
	idA = mustIdentity()
	idB = mustIdentity()
)

func mustIdentity() *crypto.Identity {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		panic(err)
	}
	return id
}

// faultConn lets a test cut a path (Close) or turn it into a blackhole
// (Freeze): writes vanish and reads deliver nothing, as on a silently
// filtered route.
type faultConn struct {
	net.Conn
	frozen atomic.Bool
}

func (c *faultConn) Freeze() { c.frozen.Store(true) }

func (c *faultConn) Read(b []byte) (int, error) {
	for {
		n, err := c.Conn.Read(b)
		if err != nil || !c.frozen.Load() {
			return n, err
		}
	}
}

func (c *faultConn) Write(b []byte) (int, error) {
	if c.frozen.Load() {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

// framePair returns two record conns joined by an in-memory pipe, plus a
// handle on the initiator's end so a test can break the path.
func framePair(t testing.TB) (*frame.Conn, *frame.Conn, *faultConn) {
	t.Helper()
	pa, pb := net.Pipe()
	ca, cb := &faultConn{Conn: pa}, &faultConn{Conn: pb}
	resp := crypto.NewResponder(idB, func([]byte) (ed25519.PublicKey, bool) { return idA.PublicKey(), true })
	type res struct {
		acc crypto.Accepted
		err error
	}
	done := make(chan res, 1)
	go func() {
		acc, err := resp.Respond(cb, func(ed25519.PublicKey, crypto.Hello) crypto.Welcome { return crypto.Welcome{} })
		done <- res{acc, err}
	}()
	keys, _, err := crypto.Initiate(ca, idA, idB.PublicKey(), crypto.Hello{NodeID: "a"})
	r := <-done
	if err != nil || r.err != nil {
		t.Fatalf("handshake: %v %v", err, r.err)
	}
	return frame.NewConn(ca, keys), frame.NewConn(cb, r.acc.Ciphers), ca
}

func testConnConfig(role Role) ConnConfig {
	return ConnConfig{
		Role:          role,
		SendBuffer:    256 << 10,
		ProbeInterval: 50 * time.Millisecond,
		DeadAfter:     400 * time.Millisecond,
		ResumeTimeout: 3 * time.Second,
	}
}

// connPair returns an initiator/responder pair joined by n paths. faults[i]
// breaks path i.
func connPair(t *testing.T, n int) (*ResumableConn, *ResumableConn, []*faultConn) {
	t.Helper()
	a, err := NewResumableConn(testConnConfig(Initiator))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewResumableConn(testConnConfig(Responder))
	if err != nil {
		t.Fatal(err)
	}
	var cuts []*faultConn
	for i := 0; i < n; i++ {
		fa, fb, raw := framePair(t)
		if _, err := b.AddPath(fb, PathMeta{Transport: "test"}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.AddPath(fa, PathMeta{Transport: "test"}); err != nil {
			t.Fatal(err)
		}
		cuts = append(cuts, raw)
	}
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b, cuts
}

// transfer sends size random bytes from w to r and returns an error if
// what arrives differs. onProgress is called once after half the data.
func transfer(w io.Writer, r io.Reader, size int, onHalf func()) error {
	data := make([]byte, size)
	_, _ = rand.Read(data)
	want := sha256.Sum256(data)
	errc := make(chan error, 1)
	go func() {
		_, err := w.Write(data)
		errc <- err
	}()
	got := make([]byte, size)
	half := false
	for n := 0; n < size; {
		k, err := r.Read(got[n:])
		if err != nil {
			return err
		}
		n += k
		if !half && n >= size/2 && onHalf != nil {
			half = true
			onHalf()
		}
	}
	if err := <-errc; err != nil {
		return err
	}
	if sha256.Sum256(got) != want {
		return errors.New("data corrupted")
	}
	return nil
}

func TestBidirectionalTransfer(t *testing.T) {
	a, b, _ := connPair(t, 1)
	const size = 4 << 20
	errc := make(chan error, 2)
	go func() { errc <- transfer(a, b, size, nil) }()
	go func() { errc <- transfer(b, a, size, nil) }()
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
}

func TestFailoverMidTransfer(t *testing.T) {
	a, b, cuts := connPair(t, 3)
	active := activePathIndex(t, a)
	err := transfer(a, b, 6<<20, func() { _ = cuts[active].Close() })
	if err != nil {
		t.Fatal(err)
	}
	// And the other direction still works on the new path.
	if err := transfer(b, a, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s := a.Stats()
	if s.Epoch < 2 || len(s.Paths) != 2 {
		t.Fatalf("expected a failover: %+v", s)
	}
}

func TestFailoverByLivenessTimeout(t *testing.T) {
	a, b, faults := connPair(t, 2)
	active := activePathIndex(t, a)
	// Only PING liveness can notice a blackhole; nothing errors.
	err := transfer(a, b, 2<<20, func() { faults[active].Freeze() })
	if err != nil {
		t.Fatal(err)
	}
	if s := a.Stats(); s.Epoch < 2 || len(s.Paths) != 1 {
		t.Fatalf("silent path was not replaced: %+v", s)
	}
}

func TestRotationMakeBeforeBreak(t *testing.T) {
	a, b, _ := connPair(t, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- transfer(a, b, 4<<20, func() {
			fa, fb, _ := framePair(t)
			if _, err := b.AddPath(fb, PathMeta{Transport: "new"}); err != nil {
				t.Error(err)
				return
			}
			id, err := a.AddPath(fa, PathMeta{Transport: "new"})
			if err != nil {
				t.Error(err)
				return
			}
			if err := a.Promote(id, true); err != nil {
				t.Error(err)
			}
		})
	}()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(a.Stats().Paths) == 1 && len(b.Stats().Paths) == 1 })
	if a.Stats().Epoch != 2 {
		t.Fatalf("epoch %d", a.Stats().Epoch)
	}
}

func TestResumeTimeout(t *testing.T) {
	a, b, cuts := connPair(t, 1)
	if err := transfer(a, b, 1000, nil); err != nil {
		t.Fatal(err)
	}
	_ = cuts[0].Close()
	select {
	case <-a.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("initiator did not time out")
	}
	<-b.Done()
	if !errors.Is(a.Err(), ErrResumeTimeout) || !errors.Is(b.Err(), ErrResumeTimeout) {
		t.Fatalf("errors %v / %v", a.Err(), b.Err())
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, ErrResumeTimeout) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestCloseNotifiesPeer(t *testing.T) {
	a, b, _ := connPair(t, 1)
	if err := transfer(a, b, 10, nil); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	select {
	case <-b.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("peer not notified")
	}
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, ErrClosedByPeer) {
		t.Fatalf("read: %v", err)
	}
}

func TestResponderCannotPromote(t *testing.T) {
	_, b, _ := connPair(t, 1)
	if err := b.Promote(1, false); !errors.Is(err, ErrNotInitiator) {
		t.Fatalf("err = %v", err)
	}
}

func TestConnConfigValidation(t *testing.T) {
	bad := []ConnConfig{
		{},
		{Role: Initiator, SendBuffer: 10, ProbeInterval: time.Second, DeadAfter: 2 * time.Second, ResumeTimeout: time.Second},
		{Role: Initiator, SendBuffer: 1 << 20, ProbeInterval: time.Second, DeadAfter: time.Second, ResumeTimeout: time.Second},
		{Role: Initiator, SendBuffer: 1 << 20, ProbeInterval: time.Second, DeadAfter: 2 * time.Second},
	}
	for i, c := range bad {
		if _, err := NewResumableConn(c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func activePathIndex(t *testing.T, c *ResumableConn) int {
	t.Helper()
	waitFor(t, func() bool { return c.Stats().Ready })
	c.mu.Lock()
	defer c.mu.Unlock()
	return int(c.active.id - 1)
}

func waitFor(t testing.TB, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func BenchmarkResumableThroughput(b *testing.B) {
	x, err := NewResumableConn(ConnConfig{Role: Initiator, SendBuffer: 4 << 20,
		ProbeInterval: time.Second, DeadAfter: 5 * time.Second, ResumeTimeout: 5 * time.Second})
	if err != nil {
		b.Fatal(err)
	}
	y, _ := NewResumableConn(ConnConfig{Role: Responder, SendBuffer: 4 << 20,
		ProbeInterval: time.Second, DeadAfter: 5 * time.Second, ResumeTimeout: 5 * time.Second})
	fa, fb, _ := framePair(b)
	_, _ = y.AddPath(fb, PathMeta{Transport: "bench"})
	_, _ = x.AddPath(fa, PathMeta{Transport: "bench"})
	defer x.Close()
	defer y.Close()
	go func() { _, _ = io.Copy(io.Discard, y) }()
	chunk := bytes.Repeat([]byte("m"), 32<<10)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := x.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}

// TestNoDeadlockWhenBothPipesFull guards against readers writing: with
// data flowing both ways and PINGs every 2 ms, a reader that answered a
// PING itself would block on a full pipe while the peer's reader did the
// same, and the transfer would hang.
func TestNoDeadlockWhenBothPipesFull(t *testing.T) {
	cfg := func(r Role) ConnConfig {
		return ConnConfig{Role: r, SendBuffer: 128 << 10, ProbeInterval: 2 * time.Millisecond,
			DeadAfter: 5 * time.Second, ResumeTimeout: 5 * time.Second}
	}
	a, _ := NewResumableConn(cfg(Initiator))
	b, _ := NewResumableConn(cfg(Responder))
	defer a.Close()
	defer b.Close()
	for i := 0; i < 2; i++ {
		fa, fb, _ := framePair(t)
		_, _ = b.AddPath(fb, PathMeta{})
		_, _ = a.AddPath(fa, PathMeta{})
	}
	errc := make(chan error, 2)
	go func() { errc <- transfer(a, b, 8<<20, nil) }()
	go func() { errc <- transfer(b, a, 8<<20, nil) }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("transfer deadlocked")
		}
	}
}
