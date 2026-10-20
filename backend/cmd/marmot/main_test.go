package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, in string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	var err error
	if args[0] == "admin" {
		err = cmdAdmin(args[1:], strings.NewReader(in), &out)
	} else {
		err = dispatch(args, &out)
	}
	return out.String(), err
}

func TestKeyAndConfigCommands(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	pub, err := run(t, "", "keygen", "-out", key)
	if err != nil || !strings.HasPrefix(pub, "ed25519:") {
		t.Fatalf("keygen %q %v", pub, err)
	}
	if _, err := run(t, "", "keygen", "-out", key); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	if again, err := run(t, "", "pubkey", "-key", key); err != nil || again != pub {
		t.Fatalf("pubkey %q %v", again, err)
	}
	if v, _ := run(t, "", "version"); strings.TrimSpace(v) != "dev" {
		t.Fatalf("version %q", v)
	}
	cfg := writeConfig(t, dir)
	if out, err := run(t, "", "check", "-config", cfg); err != nil || !strings.Contains(out, "ok (version") {
		t.Fatalf("check %q %v", out, err)
	}
	_ = os.WriteFile(filepath.Join(dir, "bad.toml"), []byte("[node]\nid = 5"), 0o600)
	if _, err := run(t, "", "check", "-config", filepath.Join(dir, "bad.toml")); err == nil {
		t.Fatal("bad config passed check")
	}
	if _, err := run(t, "", "frobnicate"); err == nil {
		t.Fatal("unknown command accepted")
	}
	if err := dispatch(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("no command accepted")
	}
}

func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "marmot.toml")
	body := fmt.Sprintf("[node]\nid = \"n1\"\nidentity_key_file = \"k\"\n[api]\nlisten = \"127.0.0.1:7443\"\ndata_dir = %q\n",
		filepath.ToSlash(filepath.Join(dir, "data")))
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHealthCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, dir)
	if _, err := run(t, "", "health", "-config", cfg); err == nil {
		t.Fatal("healthy with nothing listening")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	body := strings.Replace(mustRead(t, cfg), "127.0.0.1:7443", strings.TrimPrefix(srv.URL, "http://"), 1)
	_ = os.WriteFile(cfg, []byte(body), 0o600)
	if out, err := run(t, "", "health", "-config", cfg); err != nil || !strings.Contains(out, "ready") {
		t.Fatalf("health %q %v", out, err)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAdminCommands(t *testing.T) {
	cfg := writeConfig(t, t.TempDir())
	if _, err := run(t, "short\n", "admin", "create", "-config", cfg, "-username", "root"); err == nil {
		t.Fatal("short password accepted")
	}
	if out, err := run(t, "a-long-password-1\n", "admin", "create", "-config", cfg, "-username", "root"); err != nil || !strings.Contains(out, "created root (owner)") {
		t.Fatalf("create %q %v", out, err)
	}
	if _, err := run(t, "a-long-password-1\n", "admin", "create", "-config", cfg, "-username", "ROOT"); err == nil {
		t.Fatal("duplicate created")
	}
	t.Setenv("MARMOT_ADMIN_PASSWORD", "from-the-environment")
	if _, err := run(t, "", "admin", "create", "-config", cfg, "-username", "eye", "-role", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "", "admin", "create", "-config", cfg, "-username", "x", "-role", "god"); err == nil {
		t.Fatal("bad role accepted")
	}
	if out, err := run(t, "", "admin", "passwd", "-config", cfg, "-username", "eye"); err != nil || !strings.Contains(out, "password changed") {
		t.Fatalf("passwd %q %v", out, err)
	}
	if out, err := run(t, "", "admin", "reset-totp", "-config", cfg, "-username", "eye"); err != nil || !strings.Contains(out, "turned off") {
		t.Fatalf("reset-totp %q %v", out, err)
	}
	if _, err := run(t, "", "admin", "passwd", "-config", cfg, "-username", "ghost"); err == nil {
		t.Fatal("passwd for unknown user")
	}
	if _, err := run(t, "", "admin", "passwd", "-config", cfg); err == nil {
		t.Fatal("passwd without username")
	}
	out, err := run(t, "", "admin", "list", "-config", cfg)
	if err != nil || !strings.Contains(out, "root") || !strings.Contains(out, "viewer") {
		t.Fatalf("list %q %v", out, err)
	}
	if _, err := run(t, "", "admin", "explode", "-config", cfg); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
	if _, err := run(t, "", "admin"); err == nil {
		t.Fatal("missing subcommand accepted")
	}
}
