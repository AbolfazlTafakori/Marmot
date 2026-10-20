package frame

import (
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"testing"

	"marmot/internal/crypto"
)

// memPackets is one end of an in-memory datagram link. Sent datagrams can
// be captured to replay, drop or forge them.
type memPackets struct {
	in   chan []byte
	out  chan []byte
	sent [][]byte
	drop bool
}

func (m *memPackets) WritePacket(b []byte) error {
	c := append([]byte(nil), b...)
	m.sent = append(m.sent, c)
	if !m.drop {
		m.out <- c
	}
	return nil
}

func (m *memPackets) ReadPacket(b []byte) (int, error) {
	d, ok := <-m.in
	if !ok {
		return 0, io.EOF
	}
	return copy(b, d), nil
}

func (m *memPackets) Close() error { return nil }

func datagramPair(t *testing.T) (*DatagramConn, *DatagramConn, *memPackets, chan []byte) {
	t.Helper()
	a, b := mustID(t), mustID(t)
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	resp := crypto.NewResponder(b, func([]byte) (ed25519.PublicKey, bool) { return a.PublicKey(), true })
	done := make(chan crypto.Accepted, 1)
	go func() {
		acc, _ := resp.Respond(cb, func(ed25519.PublicKey, crypto.Hello) crypto.Welcome { return crypto.Welcome{} })
		done <- acc
	}()
	keys, _, err := crypto.Initiate(ca, a, b.PublicKey(), crypto.Hello{NodeID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	acc := <-done
	ab := make(chan []byte, 4096)
	ba := make(chan []byte, 4096)
	pa := &memPackets{in: ba, out: ab}
	pb := &memPackets{in: ab, out: ba}
	return NewDatagramConn(pa, keys, 1200), NewDatagramConn(pb, acc.Ciphers, 1200), pa, ab
}

func TestDatagramConnRoundTripAndLimits(t *testing.T) {
	a, b, _, _ := datagramPair(t)
	if err := a.WriteRecord(TypePacket, []byte("hello"), 10); err != nil {
		t.Fatal(err)
	}
	typ, body, err := b.ReadRecord()
	if err != nil || typ != TypePacket || string(body) != "hello" {
		t.Fatalf("got %v %q %v", typ, body, err)
	}
	if err := a.WriteRecord(TypePacket, make([]byte, a.MaxBody()), 0); err != nil {
		t.Fatalf("max body: %v", err)
	}
	if err := a.WriteRecord(TypePacket, make([]byte, a.MaxBody()+1), 0); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversized record: %v", err)
	}
}

func TestDatagramConnDropsReplaysAndForgeries(t *testing.T) {
	a, b, pa, wire := datagramPair(t)
	pa.drop = true
	for i := range 5 {
		if err := a.WriteRecord(TypePacket, []byte{byte(i)}, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Deliver out of order with duplicates and a forgery in between.
	forged := append([]byte(nil), pa.sent[1]...)
	forged[len(forged)-1] ^= 1
	for _, d := range [][]byte{pa.sent[3], pa.sent[3], forged, pa.sent[1], pa.sent[0], pa.sent[1], pa.sent[4], {1, 2}} {
		wire <- d
	}
	close(wire)
	var got []byte
	for {
		_, body, err := b.ReadRecord()
		if err != nil {
			break
		}
		got = append(got, body[0])
	}
	if string(got) != string([]byte{3, 1, 0, 4}) {
		t.Fatalf("delivered %v", got)
	}
	if b.Dropped != 4 {
		t.Fatalf("dropped %d, want 4", b.Dropped)
	}
}

func TestReplayWindow(t *testing.T) {
	var c DatagramConn
	accept := func(n uint64) bool {
		if !c.fresh(n) {
			return false
		}
		c.mark(n)
		return true
	}
	for _, n := range []uint64{10, 5, 2000, 2000 - replayWindow + 1, 1500} {
		if !accept(n) {
			t.Fatalf("nonce %d refused", n)
		}
	}
	for _, n := range []uint64{10, 2000, 2000 - replayWindow, 1500, 900} {
		if accept(n) {
			t.Fatalf("nonce %d accepted twice or too old", n)
		}
	}
	// A jump of exactly one word keeps the earlier bits in place.
	if !accept(2064) || accept(2000) || accept(1500) || !accept(1999) {
		t.Fatal("window shift by 64 lost track of seen nonces")
	}
	if !accept(2064+replayWindow) || !accept(2064+1) {
		t.Fatal("window did not slide past a large jump")
	}
}
