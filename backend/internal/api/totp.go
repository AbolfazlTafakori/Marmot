package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP with SHA-1 is what authenticator apps support
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters: RFC 6238 defaults, which every authenticator app uses.
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept one step before and after, for clock drift
	totpIssuer = "Marmot"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret returns a random 160-bit secret in base32.
func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// totpURI is the otpauth:// provisioning URI an authenticator app scans.
func totpURI(secret, account, node string) string {
	label := url.PathEscape(totpIssuer + ":" + account + "@" + node)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("period", fmt.Sprint(totpPeriod))
	q.Set("digits", fmt.Sprint(totpDigits))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpCode computes the code for one time step.
func totpCode(key []byte, step uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], step)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// verifyTOTP checks code against secret at time now, allowing totpSkew
// steps of drift.
func verifyTOTP(secret, code string, now time.Time) bool {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(code) != totpDigits {
		return false
	}
	step := uint64(now.Unix() / totpPeriod)
	ok := 0
	for d := -totpSkew; d <= totpSkew; d++ {
		ok |= subtle.ConstantTimeCompare([]byte(totpCode(key, uint64(int64(step)+int64(d)))), []byte(code))
	}
	return ok == 1
}
