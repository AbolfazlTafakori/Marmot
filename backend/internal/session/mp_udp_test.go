package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/transport"
	"marmot/internal/transport/udp"
)

// lossyUDP forwards one client's datagrams to server and back, dropping
// each with the given probability.
func lossyUDP(t *testing.T, server netip.AddrPort, loss float64) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sock := pc.(*net.UDPConn)
	t.Cleanup(func() { _ = sock.Close() })
	var client atomic.Pointer[netip.AddrPort]
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := sock.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if rand.Float64() < loss {
				continue
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			if from == server {
				if c := client.Load(); c != nil {
					_, _ = sock.WriteToUDPAddrPort(buf[:n], *c)
				}
				continue
			}
			client.Store(&from)
			_, _ = sock.WriteToUDPAddrPort(buf[:n], server)
		}
	}()
	return netip.MustParseAddrPort(sock.LocalAddr().String())
}

func udpServer(t *testing.T, caps uint32, fecParity int) (*Acceptor, netip.AddrPort, chan PeerSession) {
	t.Helper()
	keys, _ := NewPeerKeys(map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()})
	sessions := make(chan PeerSession, 1)
	cfg := testConnConfig(Responder)
	cfg.FECData, cfg.FECParity = 4, fecParity
	acc, err := NewAcceptor(AcceptorConfig{Local: idB, Peers: keys, Caps: caps, Conn: cfg,
		OnSession: func(s PeerSession) { sessions <- s }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acc.Close() })
	l, err := udp.Transport{}.Listen(context.Background(), transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
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
			go func() { _ = acc.Handle(context.Background(), c, PathMeta{Transport: "udp"}) }()
		}
	}()
	return acc, netip.MustParseAddrPort(l.Addr().String()), sessions
}

// TestV2OverUDP runs session v2 over two paced udp paths with 3 % random
// loss each way and FEC on (ADR-0016).
func TestV2OverUDP(t *testing.T) {
	_, addr, sessions := udpServer(t, versionCaps[2], 2)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func() transport.Conn {
		c, err := udp.Transport{}.Dial(ctx, transport.Endpoint{Addr: lossyUDP(t, addr, 0.03)}, netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cfg := testConnConfig(Initiator)
	cfg.FECData, cfg.FECParity = 4, 2
	a, err := Dial(ctx, DialConfig{Local: idA, LocalID: "a", Peer: "b", PeerKey: idB.PublicKey(),
		Caps: versionCaps[2], Conn: cfg}, dial(), PathMeta{Transport: "udp", Remote: "u0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Join(ctx, dial(), PathMeta{Transport: "udp", Remote: "u1"}, false); err != nil {
		t.Fatal(err)
	}
	b := <-sessions
	t.Cleanup(func() { _ = b.Close() })
	waitFor(t, func() bool { return len(b.Stats().Paths) == 2 })
	mp := a.(*MPSession)
	mp.mu.Lock()
	for _, p := range mp.paths {
		if !p.pace || !p.datagram {
			t.Error("udp path is not a paced datagram path")
		}
	}
	mp.mu.Unlock()
	echo(b)
	if err := roundTrip(t, a, testHeader, 4<<20, 42); err != nil {
		t.Fatal(err)
	}
	var recovered uint64
	for _, s := range []PeerSession{a, b} {
		for _, p := range s.Stats().Paths {
			recovered += p.Recovered
		}
	}
	if recovered == 0 {
		t.Fatal("FEC rebuilt nothing at 3 % loss")
	}
}

func TestV1RefusesUDP(t *testing.T) {
	_, addr, _ := udpServer(t, versionCaps[1], 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := udp.Transport{}.Dial(ctx, transport.Endpoint{Addr: addr}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Dial(ctx, DialConfig{Local: idA, LocalID: "a", Peer: "b", PeerKey: idB.PublicKey(),
		Caps: versionCaps[1], Conn: testConnConfig(Initiator)}, c, PathMeta{Transport: "udp"})
	if !errors.Is(err, errNeedsV2) {
		t.Fatalf("v1 over udp: %v", err)
	}
}
