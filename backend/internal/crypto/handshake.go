package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/flynn/noise"
)

// Prologue binds every handshake to this protocol version.
const Prologue = "marmot/1"

// MaxClockSkew is the largest accepted difference between Hello.Timestamp
// and the responder's clock.
const MaxClockSkew = 60 * time.Second

// Handshake errors.
var (
	ErrUnknownPeer  = errors.New("handshake: unknown peer key")
	ErrReplay       = errors.New("handshake: replayed or stale hello")
	ErrBadVersion   = errors.New("handshake: unsupported protocol version")
	ErrRejected     = errors.New("handshake: rejected by peer")
	ErrMsgTooLarge  = errors.New("handshake: message too large")
	errNoCipherPair = errors.New("handshake: no cipher states")
)

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// CipherPair holds the transport keys of one path. They are not safe for
// concurrent use; the record layer serialises access.
type CipherPair struct {
	Send *noise.CipherState
	Recv *noise.CipherState
}

// Initiate performs the initiator side of Noise IK over rw. The caller is
// responsible for deadlines on the underlying connection.
func Initiate(rw io.ReadWriter, local *Identity, peer ed25519.PublicKey, hello Hello) (CipherPair, Welcome, error) {
	peerX, err := X25519PublicFromEd25519(peer)
	if err != nil {
		return CipherPair{}, Welcome{}, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(Prologue),
		StaticKeypair: local.NoiseKey(),
		PeerStatic:    peerX,
	})
	if err != nil {
		return CipherPair{}, Welcome{}, fmt.Errorf("handshake init: %w", err)
	}
	hello.Version = ProtocolVersion
	if hello.Timestamp == 0 {
		hello.Timestamp = time.Now().UnixMilli()
	}
	if hello.Nonce == ([16]byte{}) {
		if _, err := rand.Read(hello.Nonce[:]); err != nil {
			return CipherPair{}, Welcome{}, err
		}
	}
	msg1, _, _, err := hs.WriteMessage(nil, hello.MarshalBinary())
	if err != nil {
		return CipherPair{}, Welcome{}, fmt.Errorf("handshake write: %w", err)
	}
	if err := writeMsg(rw, msg1); err != nil {
		return CipherPair{}, Welcome{}, err
	}
	msg2, err := readMsg(rw)
	if err != nil {
		return CipherPair{}, Welcome{}, err
	}
	payload, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return CipherPair{}, Welcome{}, fmt.Errorf("handshake read: %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return CipherPair{}, Welcome{}, errNoCipherPair
	}
	var w Welcome
	if err := w.UnmarshalBinary(payload); err != nil {
		return CipherPair{}, Welcome{}, err
	}
	if w.Status != StatusOK {
		return CipherPair{}, w, fmt.Errorf("%w (status %d)", ErrRejected, w.Status)
	}
	return CipherPair{Send: cs1, Recv: cs2}, w, nil
}

// Accepted is the result of a successful responder handshake.
type Accepted struct {
	PeerKey ed25519.PublicKey
	Hello   Hello
	Ciphers CipherPair
}

// Responder authenticates incoming handshakes against a set of known peers.
type Responder struct {
	local  *Identity
	lookup func(x25519 []byte) (ed25519.PublicKey, bool)
	replay *replayCache
	now    func() time.Time
}

// NewResponder creates a responder. lookup maps a peer's X25519 static key
// to its configured Ed25519 key and reports whether it is allowed.
func NewResponder(local *Identity, lookup func(x25519 []byte) (ed25519.PublicKey, bool)) *Responder {
	return &Responder{local: local, lookup: lookup, replay: newReplayCache(2 * MaxClockSkew), now: time.Now}
}

// Respond performs the responder side of Noise IK. decide inspects the
// authenticated Hello and returns the Welcome to send; a non-OK status is
// sent to the peer and reported as ErrRejected. Unknown peers receive no
// reply at all, so probing reveals nothing.
func (r *Responder) Respond(rw io.ReadWriter, decide func(peer ed25519.PublicKey, h Hello) Welcome) (Accepted, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      []byte(Prologue),
		StaticKeypair: r.local.NoiseKey(),
	})
	if err != nil {
		return Accepted{}, fmt.Errorf("handshake init: %w", err)
	}
	msg1, err := readMsg(rw)
	if err != nil {
		return Accepted{}, err
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		return Accepted{}, fmt.Errorf("handshake read: %w", err)
	}
	peerX := hs.PeerStatic()
	peerKey, ok := r.lookup(peerX)
	if !ok {
		return Accepted{}, ErrUnknownPeer
	}
	var h Hello
	if err := h.UnmarshalBinary(payload); err != nil {
		return Accepted{}, err
	}
	if h.Version != ProtocolVersion {
		return Accepted{}, ErrBadVersion
	}
	now := r.now()
	skew := now.Sub(time.UnixMilli(h.Timestamp))
	if skew > MaxClockSkew || skew < -MaxClockSkew || !r.replay.check(peerX, h.Nonce, now) {
		return Accepted{}, ErrReplay
	}
	w := decide(peerKey, h)
	msg2, cs1, cs2, err := hs.WriteMessage(nil, w.MarshalBinary())
	if err != nil {
		return Accepted{}, fmt.Errorf("handshake write: %w", err)
	}
	if err := writeMsg(rw, msg2); err != nil {
		return Accepted{}, err
	}
	if w.Status != StatusOK {
		return Accepted{}, fmt.Errorf("%w (status %d)", ErrRejected, w.Status)
	}
	if cs1 == nil || cs2 == nil {
		return Accepted{}, errNoCipherPair
	}
	return Accepted{PeerKey: peerKey, Hello: h, Ciphers: CipherPair{Send: cs2, Recv: cs1}}, nil
}

func writeMsg(w io.Writer, msg []byte) error {
	if len(msg) > 0xFFFF {
		return ErrMsgTooLarge
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

func readMsg(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("handshake read length: %w", err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, fmt.Errorf("handshake read body: %w", err)
	}
	return msg, nil
}
