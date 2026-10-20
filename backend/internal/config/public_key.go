package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

// PublicKeyPrefix marks an Ed25519 public key in configuration.
const PublicKeyPrefix = "ed25519:"

// ErrInvalidPublicKey is returned for malformed peer public keys.
var ErrInvalidPublicKey = errors.New("public key must be ed25519:<base64 of 32 bytes>")

// ParsePublicKey decodes "ed25519:<base64>" into an Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(s, PublicKeyPrefix)
	if !ok {
		return nil, ErrInvalidPublicKey
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(b), nil
}

// FormatPublicKey encodes an Ed25519 public key for configuration.
func FormatPublicKey(pk ed25519.PublicKey) string {
	return PublicKeyPrefix + base64.StdEncoding.EncodeToString(pk)
}

// ValidatePublicKey reports whether s is a well-formed public key.
func ValidatePublicKey(s string) error {
	_, err := ParsePublicKey(s)
	return err
}
