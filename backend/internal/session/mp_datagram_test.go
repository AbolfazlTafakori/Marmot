package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
)

// TestV2DatagramFlow sends a UDP flow's payloads both ways (ADR-0019):
// small ones as DATAGRAM frames, a large one on the stream.
func TestV2DatagramFlow(t *testing.T) {
	caps := versionCaps[2] | crypto.CapDatagrams
	ts := startServer(t, map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()}, 2)
	ts.caps = caps
	ts.acc.cfg.Caps = caps
	a, err := ts.dial(t, idA, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b := ts.next(t)
	if a.Caps()&crypto.CapDatagrams == 0 {
		t.Fatal("datagrams not negotiated")
	}
	go func() { // echo, datagram by datagram
		st, _, err := b.AcceptStream(context.Background())
		if err != nil {
			return
		}
		_, _ = st.Write([]byte{frame.ReplyOK})
		buf := make([]byte, frame.MaxDatagram)
		scratch := make([]byte, 2+frame.MaxDatagram)
		for {
			n, err := ReadDatagram(st, buf)
			if err != nil {
				return
			}
			if err := WriteDatagram(st, scratch, buf[:n]); err != nil {
				return
			}
		}
	}()
	udp := testHeader
	udp.Proto = core.ProtoUDP
	st, err := a.OpenStream(context.Background(), udp)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scratch := make([]byte, 2+frame.MaxDatagram)
	want := map[string]bool{}
	for i := range 100 {
		p := bytes.Repeat([]byte{byte(i)}, 1+i*10)
		want[string(p)] = true
		if err := WriteDatagram(st, scratch, p); err != nil {
			t.Fatal(err)
		}
	}
	big := bytes.Repeat([]byte{0xee}, 30000) // more than one packet: goes on the stream
	want[string(big)] = true
	if err := WriteDatagram(st, scratch, big); err != nil {
		t.Fatal(err)
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, frame.MaxDatagram)
	for len(want) > 0 {
		n, err := ReadDatagram(st, buf)
		if err != nil {
			t.Fatalf("%d datagrams missing: %v", len(want), err)
		}
		delete(want, string(buf[:n]))
	}
	// The small ones went beside the stream: it carried the header, the
	// big payload and its echo, not 100 more.
	if w := a.Stats().SentOff; w > 31000+64 {
		t.Fatalf("stream carried %d bytes: small datagrams were framed on it", w)
	}
}
