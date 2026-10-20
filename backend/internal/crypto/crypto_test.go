package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func mustIdentity(t testing.TB) *Identity {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func lookupFor(ids ...*Identity) func([]byte) (ed25519.PublicKey, bool) {
	m := map[string]ed25519.PublicKey{}
	for _, id := range ids {
		m[string(id.NoiseKey().Public)] = id.PublicKey()
	}
	return func(x []byte) (ed25519.PublicKey, bool) { k, ok := m[string(x)]; return k, ok }
}

type result struct {
	acc Accepted
	err error
}

func runHandshake(t *testing.T, client, server *Identity, resp *Responder, hello Hello, status uint8) (CipherPair, Welcome, result, error) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	done := make(chan result, 1)
	go func() {
		acc, err := resp.Respond(s, func(ed25519.PublicKey, Hello) Welcome {
			return Welcome{Status: status, Caps: CapUDP, ResumeOffset: 42}
		})
		if err != nil {
			s.Close()
		}
		done <- result{acc, err}
	}()
	cp, w, err := Initiate(c, client, server.PublicKey(), hello)
	return cp, w, <-done, err
}

func TestHandshakeAndTransport(t *testing.T) {
	client, server := mustIdentity(t), mustIdentity(t)
	resp := NewResponder(server, lookupFor(client))
	hello := Hello{Flags: FlagJoin, NodeID: "iran-01", Caps: CapUDP | CapRelay}
	hello.SessionID[0] = 7

	cp, w, r, err := runHandshake(t, client, server, resp, hello, StatusOK)
	if err != nil || r.err != nil {
		t.Fatalf("handshake: client %v, server %v", err, r.err)
	}
	if w.ResumeOffset != 42 || w.Caps != CapUDP {
		t.Fatalf("welcome %+v", w)
	}
	if !bytes.Equal(r.acc.PeerKey, client.PublicKey()) || r.acc.Hello.NodeID != "iran-01" || r.acc.Hello.SessionID[0] != 7 {
		t.Fatalf("accepted %+v", r.acc.Hello)
	}
	if cp.Binding != r.acc.Ciphers.Binding || cp.Binding == ([32]byte{}) {
		t.Fatalf("bindings differ or are empty: %x %x", cp.Binding, r.acc.Ciphers.Binding)
	}
	cp2, _, r2, err := runHandshake(t, client, server, resp, hello, StatusOK)
	if err != nil || r2.err != nil || cp2.Binding == cp.Binding {
		t.Fatalf("a second handshake must have its own binding: %v %v", err, r2.err)
	}
	ct, err := cp.Send.Encrypt(nil, nil, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r.acc.Ciphers.Recv.Decrypt(nil, nil, ct)
	if err != nil || string(pt) != "ping" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	ct, _ = r.acc.Ciphers.Send.Encrypt(nil, nil, []byte("pong"))
	if pt, err := cp.Recv.Decrypt(nil, nil, ct); err != nil || string(pt) != "pong" {
		t.Fatalf("decrypt reverse: %q %v", pt, err)
	}
}

func TestHandshakeUnknownPeer(t *testing.T) {
	client, server, other := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	resp := NewResponder(server, lookupFor(other))
	_, _, r, err := runHandshake(t, client, server, resp, Hello{NodeID: "x"}, StatusOK)
	if !errors.Is(r.err, ErrUnknownPeer) || err == nil {
		t.Fatalf("server %v client %v", r.err, err)
	}
}

func TestHandshakeWrongServerKey(t *testing.T) {
	client, server, impostor := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	resp := NewResponder(impostor, lookupFor(client))
	_, _, r, err := runHandshake(t, client, server, resp, Hello{NodeID: "x"}, StatusOK)
	if err == nil || r.err == nil {
		t.Fatalf("impostor accepted: client %v server %v", err, r.err)
	}
}

func TestHandshakeRejectedAndReplay(t *testing.T) {
	client, server := mustIdentity(t), mustIdentity(t)
	resp := NewResponder(server, lookupFor(client))
	_, _, r, err := runHandshake(t, client, server, resp, Hello{NodeID: "x"}, StatusOverloaded)
	if !errors.Is(err, ErrRejected) || !errors.Is(r.err, ErrRejected) {
		t.Fatalf("client %v server %v", err, r.err)
	}

	h := Hello{NodeID: "x", Timestamp: time.Now().UnixMilli()}
	h.Nonce[0] = 1
	if _, _, r, err := runHandshake(t, client, server, resp, h, StatusOK); err != nil || r.err != nil {
		t.Fatalf("first: %v %v", err, r.err)
	}
	if _, _, r, _ := runHandshake(t, client, server, resp, h, StatusOK); !errors.Is(r.err, ErrReplay) {
		t.Fatalf("replay accepted: %v", r.err)
	}
	stale := Hello{NodeID: "x", Timestamp: time.Now().Add(-2 * MaxClockSkew).UnixMilli()}
	if _, _, r, _ := runHandshake(t, client, server, resp, stale, StatusOK); !errors.Is(r.err, ErrReplay) {
		t.Fatalf("stale accepted: %v", r.err)
	}
}

func TestIdentityPersistence(t *testing.T) {
	id := mustIdentity(t)
	path := filepath.Join(t.TempDir(), "identity.key")
	if err := id.SaveIdentity(path); err != nil {
		t.Fatal(err)
	}
	if err := id.SaveIdentity(path); err == nil {
		t.Fatal("overwrote existing identity")
	}
	got, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.PublicKey(), id.PublicKey()) || !bytes.Equal(got.NoiseKey().Private, id.NoiseKey().Private) {
		t.Fatal("loaded identity differs")
	}
	msg := []byte("join")
	if !ed25519.Verify(id.PublicKey(), msg, got.Sign(msg)) {
		t.Fatal("signature does not verify")
	}
}

func TestHelloRoundTrip(t *testing.T) {
	h := Hello{Version: 1, Flags: FlagRotate, Timestamp: 123, NodeID: "node-a", Caps: 0xF}
	h.SessionID[15], h.Nonce[3] = 9, 4
	var got Hello
	if err := got.UnmarshalBinary(h.MarshalBinary()); err != nil || got != h {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if err := got.UnmarshalBinary([]byte{1, 2}); err == nil {
		t.Fatal("short hello accepted")
	}
}

func FuzzHelloUnmarshal(f *testing.F) {
	f.Add((&Hello{NodeID: "a"}).MarshalBinary())
	f.Fuzz(func(t *testing.T, b []byte) {
		var h Hello
		if h.UnmarshalBinary(b) == nil {
			var again Hello
			if err := again.UnmarshalBinary(h.MarshalBinary()); err != nil || again != h {
				t.Fatalf("re-encode mismatch: %v", err)
			}
		}
		var w Welcome
		_ = w.UnmarshalBinary(b)
	})
}
