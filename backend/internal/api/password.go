package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 second recommended option, with less
// memory so a small VPS can afford it; login is rate limited).
const (
	argonTime    = 3
	argonMemory  = 64 << 10 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// MinPasswordLen is the shortest password accepted for an administrator.
const MinPasswordLen = 12

var errBadHash = errors.New("api: malformed password hash")

// HashPassword returns a PHC-format argon2id hash of password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches hash, in constant time.
// Parameters are read from the hash, so stronger settings later still
// verify old hashes.
func VerifyPassword(hash, password string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil || mem == 0 || t == 0 || p == 0 {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when the username does not exist, so a
// login attempt takes as long either way and does not reveal which
// usernames exist.
var dummyHash = sync.OnceValue(func() string {
	h, _ := HashPassword("marmot-timing-equaliser")
	return h
})
