package session

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/transport"
	"marmot/internal/transport/quic"
)

// TestV2OverQUIC runs session v2 over real QUIC connections: records go in
// datagrams, with FEC, and a stream round trip must come out intact.
func TestV2OverQUIC(t *testing.T) {
	keys, _ := NewPeerKeys(map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()})
	sessions := make(chan PeerSession, 1)
	cfg := testConnConfig(Responder)
	cfg.FECData, cfg.FECParity = 4, 1
	acc, err := NewAcceptor(AcceptorConfig{Local: idB, Peers: keys, Caps: versionCaps[2], Conn: cfg,
		OnSession: func(s PeerSession) { sessions <- s }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := quic.Transport{}.Listen(ctx, transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = acc.Handle(context.Background(), c, PathMeta{Transport: "quic"}) }()
		}
	}()
	addr := netip.MustParseAddrPort(l.Addr().String())
	dial := func() transport.Conn {
		c, err := quic.Transport{}.Dial(ctx, transport.Endpoint{Addr: addr}, netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	acfg := testConnConfig(Initiator)
	acfg.FECData, acfg.FECParity = 4, 1
	a, err := Dial(ctx, DialConfig{Local: idA, LocalID: "a", Peer: "b", PeerKey: idB.PublicKey(),
		Caps: versionCaps[2], Conn: acfg}, dial(), PathMeta{Transport: "quic", Remote: "q0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Join(ctx, dial(), PathMeta{Transport: "quic", Remote: "q1"}, false); err != nil {
		t.Fatal(err)
	}
	b := <-sessions
	t.Cleanup(func() { _ = b.Close() })
	waitFor(t, func() bool { return len(b.Stats().Paths) == 2 })
	for _, p := range a.Stats().Paths {
		if !p.Datagram {
			t.Fatalf("path %s is not a datagram path", p.Meta)
		}
	}
	echo(b)
	for i := range 3 {
		if err := roundTrip(t, a, testHeader, 1<<20, uint64(100+i)); err != nil {
			t.Fatal(fmt.Errorf("round trip %d: %w", i, err))
		}
	}
}
