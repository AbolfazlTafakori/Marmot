package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
	"marmot/internal/transport"
	"marmot/internal/transport/tcp"
)

type testServer struct {
	acc      *Acceptor
	addr     netip.AddrPort
	sessions chan *MuxSession
}

// startServer runs an acceptor for node "b" that knows the given peers.
func startServer(t *testing.T, peers map[core.NodeID]ed25519.PublicKey) *testServer {
	t.Helper()
	keys, err := NewPeerKeys(peers)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{sessions: make(chan *MuxSession, 4)}
	ts.acc, err = NewAcceptor(AcceptorConfig{
		Local: idB, Peers: keys, Caps: crypto.CapUDP,
		Conn:      testConnConfig(Responder),
		OnSession: func(s *MuxSession) { ts.sessions <- s },
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := tcp.Transport{}.Listen(context.Background(), transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	ts.addr = netip.MustParseAddrPort(l.Addr().String())
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = ts.acc.Handle(context.Background(), c, PathMeta{Transport: "tcp"}) }()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		_ = ts.acc.Close()
	})
	return ts
}

func (ts *testServer) dialRaw(t *testing.T) transport.Conn {
	t.Helper()
	c, err := tcp.Transport{}.Dial(context.Background(), transport.Endpoint{Addr: ts.addr}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (ts *testServer) dial(t *testing.T, local *crypto.Identity, localID core.NodeID) (*MuxSession, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Dial(ctx, DialConfig{
		Local: local, LocalID: localID, Peer: "b", PeerKey: idB.PublicKey(),
		Caps: crypto.CapUDP | crypto.CapRelay, Conn: testConnConfig(Initiator),
	}, ts.dialRaw(t), PathMeta{Transport: "tcp"})
}

func (ts *testServer) next(t *testing.T) *MuxSession {
	t.Helper()
	select {
	case s := <-ts.sessions:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no inbound session")
		return nil
	}
}

var testHeader = frame.StreamHeader{Proto: core.ProtoTCP, Class: core.ClassTunneled, TargetPort: 443,
	Client: netip.MustParseAddrPort("203.0.113.5:40000")}

func TestStreamEndToEnd(t *testing.T) {
	ts := startServer(t, map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()})
	a, err := ts.dial(t, idA, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b := ts.next(t)
	if b.Peer() != "a" || a.Caps() != crypto.CapUDP || b.Caps() != crypto.CapUDP {
		t.Fatalf("peer %q caps %b/%b", b.Peer(), a.Caps(), b.Caps())
	}

	go func() {
		for {
			st, h, err := b.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer st.Close()
				if h.TargetPort == 9 {
					_, _ = st.Write([]byte{frame.ReplyRefused})
					return
				}
				if !reflect.DeepEqual(h, testHeader) {
					t.Errorf("header %+v", h)
				}
				_, _ = st.Write([]byte{frame.ReplyOK})
				_, _ = io.Copy(st, st)
			}()
		}
	}()

	ctx := context.Background()
	st, err := a.OpenStream(ctx, testHeader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(st, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q %v", got, err)
	}
	_ = st.Close()

	refused := testHeader
	refused.TargetPort = 9
	st, err = a.OpenStream(ctx, refused)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Read(got); !IsReplyError(err) {
		t.Fatalf("refused stream read: %v", err)
	}
}

func TestJoinAddsStandbyPath(t *testing.T) {
	ts := startServer(t, map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()})
	a, err := ts.dial(t, idA, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b := ts.next(t)
	if err := a.Join(context.Background(), ts.dialRaw(t), PathMeta{Transport: "tcp"}, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(b.Stats().Paths) == 2 })
	if err := a.Join(context.Background(), ts.dialRaw(t), PathMeta{Transport: "tcp"}, true); err != nil {
		t.Fatal(err)
	}
	// The rotated-out path is closed on both sides.
	waitFor(t, func() bool { return len(a.Stats().Paths) == 2 && len(b.Stats().Paths) == 2 })
	if a.Stats().Epoch != 2 {
		t.Fatalf("epoch %d", a.Stats().Epoch)
	}
}

func TestJoinOtherPeersSessionRejected(t *testing.T) {
	idC := mustIdentity()
	ts := startServer(t, map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey(), "c": idC.PublicKey()})
	a, err := ts.dial(t, idA, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ts.next(t)
	// C knows A's session id and tries to attach a path to it.
	hijack := &MuxSession{id: a.ID(), local: idC, localID: "c", peerKey: idB.PublicKey(), role: Initiator}
	err = hijack.Join(context.Background(), ts.dialRaw(t), PathMeta{}, false)
	if !errors.Is(err, crypto.ErrRejected) {
		t.Fatalf("hijack join: %v", err)
	}
}

func TestUnknownPeerRejected(t *testing.T) {
	ts := startServer(t, map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()})
	if _, err := ts.dial(t, mustIdentity(), "x"); err == nil {
		t.Fatal("unknown peer was accepted")
	}
}

func TestRevocationClosesSession(t *testing.T) {
	ts := startServer(t, map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey()})
	a, err := ts.dial(t, idA, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b := ts.next(t)
	waitFor(t, func() bool { return a.Stats().Ready })
	empty, _ := NewPeerKeys(nil)
	ts.acc.SetPeers(empty)
	for _, s := range []*MuxSession{a, b} {
		select {
		case <-s.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("session survived revocation")
		}
	}
	if len(ts.acc.Sessions()) != 0 {
		waitFor(t, func() bool { return len(ts.acc.Sessions()) == 0 })
	}
}

func TestPeerKeysRejectsSharedKey(t *testing.T) {
	_, err := NewPeerKeys(map[core.NodeID]ed25519.PublicKey{"a": idA.PublicKey(), "b": idA.PublicKey()})
	if err == nil {
		t.Fatal("shared key accepted")
	}
}
