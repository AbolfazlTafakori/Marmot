package api

import (
	"strings"
	"testing"
	"time"

	"marmot/internal/config"
	"marmot/internal/crypto"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("hash %s", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); !ok || err != nil {
		t.Fatal("right password rejected", err)
	}
	if ok, _ := VerifyPassword(h, "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h2 == h {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=1$m=1,t=1,p=1$AA$AA",
		"$argon2id$v=19$m=0,t=1,p=1$AA$AA", "$argon2id$v=19$m=1,t=1,p=1$!!$AA", "$argon2id$v=19$m=1,t=1,p=1$AA$"} {
		if _, err := VerifyPassword(bad, "x"); err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

// RFC 6238 appendix B, SHA-1 key, truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	secret := b32.EncodeToString(key)
	vectors := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range vectors {
		if got := totpCode(key, uint64(ts/30)); got != want {
			t.Errorf("t=%d: %s want %s", ts, got, want)
		}
		if !verifyTOTP(secret, want, time.Unix(ts, 0)) {
			t.Errorf("t=%d: verify failed", ts)
		}
		if !verifyTOTP(secret, want, time.Unix(ts+30, 0)) {
			t.Errorf("t=%d: one step of drift not tolerated", ts)
		}
		if verifyTOTP(secret, want, time.Unix(ts+90, 0)) {
			t.Errorf("t=%d: three steps of drift tolerated", ts)
		}
	}
	if verifyTOTP("not base32!", "123456", time.Now()) || verifyTOTP(secret, "12345", time.Now()) {
		t.Fatal("bad input accepted")
	}
	s, _ := newTOTPSecret()
	uri := totpURI(s, "admin", "iran-01")
	if !strings.HasPrefix(uri, "otpauth://totp/Marmot:admin@iran-01?") || !strings.Contains(uri, "secret="+s) {
		t.Fatalf("uri %s", uri)
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	rl := newRateLimiter(3, time.Minute)
	rl.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if b, _ := rl.blocked("k"); b {
			t.Fatalf("blocked after %d failures", i)
		}
		rl.fail("k")
		now = now.Add(10 * time.Second)
	}
	b, wait := rl.blocked("k")
	if !b || wait != 30*time.Second {
		t.Fatalf("blocked=%v wait=%v", b, wait)
	}
	now = now.Add(31 * time.Second)
	if b, _ := rl.blocked("k"); b {
		t.Fatal("still blocked after the oldest failure left the window")
	}
	rl.fail("k")
	rl.reset("k")
	rl.fail("other")
	now = now.Add(2 * time.Minute)
	rl.sweep()
	if len(rl.fails) != 0 {
		t.Fatalf("sweep left %v", rl.fails)
	}
}

func TestJoinToken(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	c := &config.Config{
		Node:  config.Node{ID: "kharej-01"},
		Local: config.Local{IPv4Pool: []string{"198.51.100.7"}},
		TransportListen: []config.TransportListen{
			{Transport: "tls", Port: 9443, Options: map[string]any{"sni": "cdn.example.com", "cert_file": "/etc/secret.pem"}},
			{Transport: "tls", Port: 2083},
			{Transport: "quic", PortRange: config.PortRange{Lo: 40000, Hi: 40010}},
		},
	}
	tok, err := makeJoinToken(c, id.PublicKey(), id.Sign, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseJoinToken(" "+tok+"\n", 7)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "kharej-01" || p.Weight != 7 || p.PublicKey != config.FormatPublicKey(id.PublicKey()) ||
		len(p.Endpoints) != 1 || len(p.Endpoints[0].Ports) != 2 || p.Endpoints[0].Options["sni"] != "cdn.example.com" {
		t.Fatalf("peer %+v", p)
	}
	if _, leaked := p.Endpoints[0].Options["cert_file"]; leaked {
		t.Fatal("certificate path exported in join token")
	}
	// Any edit breaks the signature.
	body := tok[len(joinTokenPrefix):strings.LastIndex(tok, ".")]
	tampered := joinTokenPrefix + body[:len(body)-2] + "AA" + tok[strings.LastIndex(tok, "."):]
	for _, bad := range []string{tampered, "mt2." + tok[4:], "mt1.x", "mt1.!.!", tok + "A"} {
		if _, err := parseJoinToken(bad, 1); err == nil {
			t.Errorf("token %.20q accepted", bad)
		}
	}
	// Without addresses the peer is inbound-only.
	c.Local.IPv4Pool = nil
	tok, _ = makeJoinToken(c, id.PublicKey(), id.Sign, time.Unix(1, 0))
	if p, _ := parseJoinToken(tok, 1); len(p.Endpoints) != 0 {
		t.Fatalf("addressless token has endpoints %+v", p.Endpoints)
	}
}

func TestValidUsername(t *testing.T) {
	for _, ok := range []string{"abc", "admin.root", "a_b-c", strings.Repeat("x", 32)} {
		if validUsername(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"ab", strings.Repeat("x", 33), "a b", "a/b", "علی"} {
		if validUsername(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
