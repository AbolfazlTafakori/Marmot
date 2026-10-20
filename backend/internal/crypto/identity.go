// Package crypto holds node identity keys and the Noise IK handshake that
// authenticates every path between two nodes.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/edwards25519"
	"github.com/flynn/noise"
)

// Identity is a node's long-term key pair: Ed25519 for identity and
// signatures, and the X25519 key derived from it for Noise.
type Identity struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	noise noise.DHKey
}

// GenerateIdentity creates a new random identity.
func GenerateIdentity() (*Identity, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate seed: %w", err)
	}
	return IdentityFromSeed(seed)
}

// IdentityFromSeed builds an identity from a 32-byte Ed25519 seed.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("identity seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	xpub, err := X25519PublicFromEd25519(pub)
	if err != nil {
		return nil, err
	}
	return &Identity{
		priv:  priv,
		pub:   pub,
		noise: noise.DHKey{Private: x25519PrivateFromSeed(seed), Public: xpub},
	}, nil
}

// PublicKey returns the Ed25519 public key.
func (id *Identity) PublicKey() ed25519.PublicKey { return id.pub }

// Sign signs msg with the Ed25519 key.
func (id *Identity) Sign(msg []byte) []byte { return ed25519.Sign(id.priv, msg) }

// NoiseKey returns the X25519 static key used in handshakes.
func (id *Identity) NoiseKey() noise.DHKey { return id.noise }

// LoadIdentity reads a base64-encoded seed from path.
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode identity %s: %w", path, err)
	}
	return IdentityFromSeed(seed)
}

// SaveIdentity writes the seed to path with owner-only permissions. It
// refuses to overwrite an existing file.
func (id *Identity) SaveIdentity(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create identity: %w", err)
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(id.priv.Seed()) + "\n")
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("write identity: %w", werr)
	}
	return cerr
}

// X25519PublicFromEd25519 converts an Ed25519 public key to its X25519
// (Montgomery) form.
func X25519PublicFromEd25519(pub ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key: %w", err)
	}
	return p.BytesMontgomery(), nil
}

// x25519PrivateFromSeed derives the X25519 scalar matching the Ed25519 key
// (same as libsodium crypto_sign_ed25519_sk_to_curve25519).
func x25519PrivateFromSeed(seed []byte) []byte {
	h := sha512.Sum512(seed)
	s := make([]byte, 32)
	copy(s, h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}
