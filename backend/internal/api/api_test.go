package api

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"marmot/internal/config"
	"marmot/internal/crypto"
	"marmot/internal/node"
	"marmot/internal/store"

	_ "marmot/internal/transport/tcp"
	_ "marmot/internal/transport/tls"
)

const ownerPassword = "owner-password-123"

type fixture struct {
	t       *testing.T
	dir     string
	cfgPath string
	node    *node.Node
	store   *store.Store
	srv     *Server
	ts      *httptest.Server
	userPrt uint16
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// freeTCPUDPPort returns a port that is free for both TCP and UDP. On
// Windows a TCP-free port can sit in a range reserved for UDP (Hyper-V).
func freeTCPUDPPort(t *testing.T) uint16 {
	t.Helper()
	for i := 0; i < 50; i++ {
		p := freePort(t)
		u, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(p)})
		if err == nil {
			_ = u.Close()
			return p
		}
	}
	t.Fatal("no port free for both TCP and UDP")
	return 0
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir()}
	web := filepath.Join(f.dir, "web")
	_ = os.MkdirAll(filepath.Join(web, "assets"), 0o755)
	_ = os.WriteFile(filepath.Join(web, "index.html"), []byte("<!doctype html><title>Marmot</title>"), 0o644)
	_ = os.WriteFile(filepath.Join(web, "assets", "app-1234.js"), []byte("console.log(1)"), 0o644)

	id, _ := crypto.GenerateIdentity()
	keyFile := filepath.Join(f.dir, "identity.key")
	if err := id.SaveIdentity(keyFile); err != nil {
		t.Fatal(err)
	}
	f.userPrt = freePort(t)
	toml := fmt.Sprintf(`# hand-written comment
[node]
id = "iran-01"
identity_key_file = %q
[steering]
tunneled_ports = [%d]
[local]
ipv4_pool = ["127.0.0.1"]
[[transport_listen]]
transport = "tls"
port = %d
options = { sni = "cdn.example.com" }
[api]
listen = "127.0.0.1:%d"
data_dir = %q
web_root = %q
`, filepath.ToSlash(keyFile), f.userPrt, freePort(t), freePort(t), filepath.ToSlash(filepath.Join(f.dir, "data")), filepath.ToSlash(web))
	f.cfgPath = filepath.Join(f.dir, "marmot.toml")
	if err := os.WriteFile(f.cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	f.node, err = node.New(loaded.Config, id, node.Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.node.Start(); err != nil {
		t.Fatal(err)
	}
	f.store, err = store.Open(context.Background(), loaded.Config.API.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	f.addAdmin("root", ownerPassword, store.RoleOwner)
	f.srv, err = New(Config{Node: f.node, Store: f.store, ConfigPath: f.cfgPath, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	f.ts = httptest.NewServer(f.srv.Handler())
	t.Cleanup(func() {
		f.ts.Close()
		_ = f.node.Stop()
		_ = f.store.Close()
	})
	return f
}

func (f *fixture) addAdmin(user, pass string, role store.Role) *store.Admin {
	h, err := HashPassword(pass)
	if err != nil {
		f.t.Fatal(err)
	}
	a := &store.Admin{Username: user, PasswordHash: h, Role: role}
	if err := f.store.CreateAdmin(context.Background(), a); err != nil {
		f.t.Fatal(err)
	}
	return a
}

type client struct {
	f    *fixture
	hc   *http.Client
	csrf string
}

func (f *fixture) anon() *client {
	jar, _ := cookiejar.New(nil)
	return &client{f: f, hc: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

func (f *fixture) login(user, pass string) *client {
	f.t.Helper()
	c := f.anon()
	var me meView
	if code := c.do("POST", "/api/v1/auth/login", loginRequest{Username: user, Password: pass}, &me); code != 200 {
		f.t.Fatalf("login %s: %d", user, code)
	}
	c.csrf = me.CSRFToken
	return c
}

// do sends a JSON request and decodes the response into out (if non-nil).
func (c *client) do(method, path string, body, out any) int {
	c.f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.f.ts.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set(csrfHeader, c.csrf)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.f.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			c.f.t.Fatalf("%s %s: decode %q: %v", method, path, data, err)
		}
	}
	return resp.StatusCode
}

func TestHealthAndAuthGate(t *testing.T) {
	f := newFixture(t)
	c := f.anon()
	for _, p := range []string{"/healthz", "/readyz", "/api/v1/healthz", "/api/v1/readyz"} {
		if code := c.do("GET", p, nil, nil); code != 200 {
			t.Errorf("%s: %d", p, code)
		}
	}
	var e errorView
	if code := c.do("GET", "/api/v1/node/status", nil, &e); code != 401 || e.Code != "unauthorized" {
		t.Fatalf("status without login: %d %+v", code, e)
	}
	if code := c.do("GET", "/api/v1/nope", nil, &e); code != 404 || e.Code != "not_found" {
		t.Fatalf("unknown api path: %d %+v", code, e)
	}
}

func TestLoginLogoutAndCSRF(t *testing.T) {
	f := newFixture(t)
	c := f.anon()
	var e errorView
	if code := c.do("POST", "/api/v1/auth/login", loginRequest{Username: "root", Password: "nope"}, &e); code != 401 || e.Code != "invalid_credentials" {
		t.Fatalf("wrong password: %d %+v", code, e)
	}
	if code := c.do("POST", "/api/v1/auth/login", loginRequest{Username: "ghost", Password: "nope"}, &e); code != 401 || e.Code != "invalid_credentials" {
		t.Fatalf("unknown user: %d %+v", code, e)
	}
	c = f.login("ROOT", ownerPassword) // usernames are case-insensitive
	var me meView
	if code := c.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.Username != "root" || me.Role != "owner" || me.CSRFToken == "" || me.Locale != "fa" {
		t.Fatalf("me: %d %+v", code, me)
	}
	good := c.csrf
	c.csrf = ""
	if code := c.do("POST", "/api/v1/node/reload", nil, &e); code != 403 || e.Code != "csrf" {
		t.Fatalf("missing csrf: %d %+v", code, e)
	}
	c.csrf = "wrong"
	if code := c.do("POST", "/api/v1/node/reload", nil, &e); code != 403 || e.Code != "csrf" {
		t.Fatalf("wrong csrf: %d %+v", code, e)
	}
	c.csrf = good
	if code := c.do("POST", "/api/v1/node/reload", nil, nil); code != 204 {
		t.Fatalf("reload: %d", code)
	}
	if code := c.do("POST", "/api/v1/auth/logout", nil, nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code := c.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("me after logout: %d", code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	f := newFixture(t)
	c := f.anon()
	for i := 0; i < loginLimitPerUser; i++ {
		c.do("POST", "/api/v1/auth/login", loginRequest{Username: "root", Password: "guess"}, nil)
	}
	req, _ := http.NewRequest("POST", f.ts.URL+"/api/v1/auth/login",
		strings.NewReader(`{"username":"root","password":"`+ownerPassword+`"}`))
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("after %d failures: %d retry-after %q", loginLimitPerUser, resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	var page auditPageView
	f.srv.loginUser.reset("root")
	f.srv.loginIP.reset("127.0.0.1")
	owner := f.login("root", ownerPassword)
	owner.do("GET", "/api/v1/audit?limit=200", nil, &page)
	fails := 0
	for _, it := range page.Items {
		if it.Action == "login.fail" {
			fails++
		}
	}
	if fails != loginLimitPerUser {
		t.Fatalf("audited %d failed logins", fails)
	}
}

func TestTOTPEnrolmentAndLogin(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	var res struct{ URI string }
	if code := c.do("POST", "/api/v1/auth/totp", nil, &res); code != 200 {
		t.Fatalf("start: %d", code)
	}
	u, err := url.Parse(res.URI)
	if err != nil || u.Scheme != "otpauth" {
		t.Fatalf("uri %q", res.URI)
	}
	secret := u.Query().Get("secret")
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	code := func() string { return totpCode(key, uint64(time.Now().Unix()/30)) }

	if st := c.do("PUT", "/api/v1/auth/totp", map[string]string{"code": "000000"}, nil); st != 400 {
		t.Fatalf("wrong code accepted: %d", st)
	}
	if st := c.do("PUT", "/api/v1/auth/totp", map[string]string{"code": code()}, nil); st != 204 {
		t.Fatalf("confirm: %d", st)
	}
	if st := c.do("POST", "/api/v1/auth/totp", nil, nil); st != 409 {
		t.Fatalf("second enrolment: %d", st)
	}

	a := f.anon()
	var e errorView
	if st := a.do("POST", "/api/v1/auth/login", loginRequest{Username: "root", Password: ownerPassword}, &e); st != 401 || e.Code != "totp_required" {
		t.Fatalf("login without code: %d %+v", st, e)
	}
	if st := a.do("POST", "/api/v1/auth/login", loginRequest{Username: "root", Password: ownerPassword, TOTP: "123456"}, &e); st != 401 || e.Code != "invalid_totp" {
		t.Fatalf("login with wrong code: %d %+v", st, e)
	}
	var me meView
	if st := a.do("POST", "/api/v1/auth/login", loginRequest{Username: "root", Password: ownerPassword, TOTP: code()}, &me); st != 200 || !me.TOTPEnabled {
		t.Fatalf("login with code: %d %+v", st, me)
	}
	a.csrf = me.CSRFToken
	if st := a.do("DELETE", "/api/v1/auth/totp?code=000000", nil, nil); st != 400 {
		t.Fatalf("disable with wrong code: %d", st)
	}
	if st := a.do("DELETE", "/api/v1/auth/totp?code="+code(), nil, nil); st != 204 {
		t.Fatalf("disable: %d", st)
	}
	f.login("root", ownerPassword) // no code needed again
}

func TestStatusIdentityMetrics(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	var st nodeStatusView
	if code := c.do("GET", "/api/v1/node/status", nil, &st); code != 200 || st.NodeID != "iran-01" || st.Version != "test" || st.Role != "hybrid" {
		t.Fatalf("status %d %+v", code, st)
	}
	var id identityView
	if code := c.do("GET", "/api/v1/node/identity", nil, &id); code != 200 || !strings.HasPrefix(id.PublicKey, "ed25519:") {
		t.Fatalf("identity %d %+v", code, id)
	}
	p, err := parseJoinToken(id.JoinToken, 1)
	if err != nil || p.ID != "iran-01" || len(p.Endpoints) != 1 || p.Endpoints[0].Options["sni"] != "cdn.example.com" {
		t.Fatalf("own join token: %+v %v", p, err)
	}
	found := map[string]float64{}
	for _, m := range Metrics(f.node) {
		if len(m.Samples) > 0 {
			found[m.Name] = m.Samples[0].Value
		}
	}
	if found["marmot_up"] != 1 || found["marmot_go_goroutines"] < 1 || found["marmot_go_heap_inuse_bytes"] <= 0 {
		t.Fatalf("metrics %v", found)
	}
}

func TestConfigEndpoints(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	var doc configDocument
	if code := c.do("GET", "/api/v1/config", nil, &doc); code != 200 || !strings.Contains(doc.TOML, "hand-written comment") {
		t.Fatalf("get %d %+v", code, doc)
	}

	var vr validationResult
	c.do("POST", "/api/v1/config/validate", configDocument{TOML: "[node]\nid = \"X\""}, &vr)
	if vr.Valid || len(vr.Issues) == 0 {
		t.Fatalf("invalid config validated: %+v", vr)
	}
	c.do("POST", "/api/v1/config/validate", configDocument{TOML: doc.TOML}, &vr)
	if !vr.Valid {
		t.Fatalf("valid config rejected: %+v", vr)
	}

	edited := strings.Replace(doc.TOML, "[local]", "[telemetry]\nlog_level = \"debug\"\n[local]", 1)
	if code := c.do("PUT", "/api/v1/config", configDocument{TOML: edited, Version: "stale"}, nil); code != 409 {
		t.Fatalf("stale version: %d", code)
	}
	if code := c.do("PUT", "/api/v1/config", configDocument{TOML: "garbage = [", Version: doc.Version}, &vr); code != 422 || vr.Valid {
		t.Fatalf("invalid put: %d %+v", code, vr)
	}
	renamed := strings.Replace(doc.TOML, `id = "iran-01"`, `id = "iran-02"`, 1)
	if code := c.do("PUT", "/api/v1/config", configDocument{TOML: renamed, Version: doc.Version}, &vr); code != 422 || vr.Issues[0].Path != "node.id" {
		t.Fatalf("node id change: %d %+v", code, vr)
	}
	if b, _ := os.ReadFile(f.cfgPath); string(b) != doc.TOML {
		t.Fatal("a rejected config reached the disk")
	}
	var out configDocument
	if code := c.do("PUT", "/api/v1/config", configDocument{TOML: edited, Version: doc.Version}, &out); code != 200 || out.Version == doc.Version {
		t.Fatalf("put: %d %+v", code, out)
	}
	if b, _ := os.ReadFile(f.cfgPath); string(b) != edited {
		t.Fatal("file not written as sent")
	}
	if f.node.Config().Telemetry.LogLevel != "debug" {
		t.Fatal("config not applied to the node")
	}
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".marmot.toml.") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSteeringEndpoints(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	var sv steeringView
	if code := c.do("GET", "/api/v1/steering", nil, &sv); code != 200 || len(sv.Ports) != 1 || sv.BypassNote == "" {
		t.Fatalf("get %d %+v", code, sv)
	}
	newPort := int(freeTCPUDPPort(t)) // the vip rule binds both
	req := steeringView{Ports: []portRuleView{
		{Port: int(f.userPrt), Class: "tunneled", Protocols: []string{"tcp"}},
		{Port: newPort, Class: "vip", Protocols: []string{"udp", "tcp"}, TargetPort: 62050},
	}}
	if code := c.do("PUT", "/api/v1/steering", req, &sv); code != 200 || len(sv.Ports) != 2 || len(sv.Warnings) != 0 {
		t.Fatalf("put %d %+v", code, sv)
	}
	// Rules come back sorted by port, so find the new one by its number.
	var added *portRuleView
	for i := range sv.Ports {
		if sv.Ports[i].Port == newPort {
			added = &sv.Ports[i]
		}
	}
	if added == nil || added.Class != "vip" || added.TargetPort != 62050 || len(added.Protocols) != 2 {
		t.Fatalf("rules %+v", sv.Ports)
	}
	if conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", newPort)); err != nil {
		t.Fatalf("new port not bound: %v", err)
	} else {
		conn.Close()
	}
	b, _ := os.ReadFile(f.cfgPath)
	if !strings.Contains(string(b), "vip_control_ports") || !strings.Contains(string(b), "62050") {
		t.Fatalf("file:\n%s", b)
	}

	// A port held by someone else: saved, applied elsewhere, warned about.
	busy, _ := net.Listen("tcp", ":0") // all addresses, as steering binds
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	req.Ports = append(req.Ports, portRuleView{Port: busyPort, Class: "tunneled", Protocols: []string{"tcp"}})
	if code := c.do("PUT", "/api/v1/steering", req, &sv); code != 200 || len(sv.Warnings) == 0 {
		t.Fatalf("busy port: %d %+v", code, sv)
	}

	var vr validationResult
	bad := steeringView{Ports: []portRuleView{{Port: 22, Class: "tunneled", Protocols: []string{"tcp"}}}}
	if code := c.do("PUT", "/api/v1/steering", bad, &vr); code != 422 || vr.Valid {
		t.Fatalf("ssh port: %d %+v", code, vr)
	}
	bad = steeringView{Ports: []portRuleView{{Port: 9, Class: "gold", Protocols: []string{"tcp"}}}}
	if code := c.do("PUT", "/api/v1/steering", bad, &vr); code != 422 || vr.Issues[0].Path != "ports[0].class" {
		t.Fatalf("bad class: %d %+v", code, vr)
	}
}

func TestPeerEndpoints(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	other, _ := crypto.GenerateIdentity()
	pk := config.FormatPublicKey(other.PublicKey())
	peer := peerView{ID: "kharej-01", PublicKey: pk, Weight: 3, IPv4Pool: []string{"127.0.0.1"},
		Endpoints: []endpointView{{Transport: "tls", Ports: []int{int(freePort(t))}, Direction: "outbound",
			Options: map[string]any{"sni": "a.example"}}}}
	var pv peerView
	if code := c.do("POST", "/api/v1/peers", peer, &pv); code != 201 || pv.ID != "kharej-01" || pv.Health == nil {
		t.Fatalf("create %d %+v", code, pv)
	}
	if code := c.do("POST", "/api/v1/peers", peer, nil); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	var list []peerView
	if code := c.do("GET", "/api/v1/peers", nil, &list); code != 200 || len(list) != 1 || list[0].Endpoints[0].Direction != "outbound" {
		t.Fatalf("list %d %+v", code, list)
	}
	peer.Weight = 9
	if code := c.do("PUT", "/api/v1/peers/kharej-01", peer, &pv); code != 200 || pv.Weight != 9 {
		t.Fatalf("update %d %+v", code, pv)
	}
	if code := c.do("PUT", "/api/v1/peers/other", peer, nil); code != 400 {
		t.Fatalf("rename via update: %d", code)
	}
	var paths []pathView
	if code := c.do("GET", "/api/v1/peers/kharej-01/paths", nil, &paths); code != 200 {
		t.Fatalf("paths %d", code)
	}
	var vr validationResult
	in := peer
	in.ID = "rev"
	in.Endpoints = []endpointView{{Transport: "tls", Ports: []int{1}, Direction: "inbound"}}
	if code := c.do("POST", "/api/v1/peers", in, &vr); code != 422 || !strings.Contains(vr.Issues[0].Path, "direction") {
		t.Fatalf("inbound direction: %d %+v", code, vr)
	}
	in.Endpoints = nil
	in.PublicKey = "ed25519:bad"
	if code := c.do("POST", "/api/v1/peers", in, &vr); code != 422 {
		t.Fatalf("bad key: %d %+v", code, vr)
	}

	// Import through a join token made by another node.
	third, _ := crypto.GenerateIdentity()
	tokCfg := &config.Config{Node: config.Node{ID: "kharej-02"}, Local: config.Local{IPv4Pool: []string{"192.0.2.9"}},
		TransportListen: []config.TransportListen{{Transport: "tls", Port: 9443}}}
	tok, _ := makeJoinToken(tokCfg, third.PublicKey(), third.Sign, time.Now())
	if code := c.do("POST", "/api/v1/peers", joinRequest{JoinToken: tok, Weight: 4}, &pv); code != 201 || pv.ID != "kharej-02" || pv.Weight != 4 || pv.Endpoints[0].Ports[0] != 9443 {
		t.Fatalf("join import %d %+v", code, pv)
	}
	if code := c.do("POST", "/api/v1/peers", joinRequest{JoinToken: tok[:len(tok)-3] + "xyz"}, nil); code != 400 {
		t.Fatalf("tampered token: %d", code)
	}

	if code := c.do("DELETE", "/api/v1/peers/kharej-01", nil, nil); code != 204 {
		t.Fatalf("delete %d", code)
	}
	if code := c.do("DELETE", "/api/v1/peers/kharej-01", nil, nil); code != 404 {
		t.Fatalf("delete again %d", code)
	}
	if code := c.do("GET", "/api/v1/peers/kharej-01", nil, nil); code != 404 {
		t.Fatalf("get deleted %d", code)
	}
	if code := c.do("GET", "/api/v1/peers/kharej-01/paths", nil, nil); code != 404 {
		t.Fatalf("paths of deleted %d", code)
	}
}

func TestRolesAdminsAudit(t *testing.T) {
	f := newFixture(t)
	owner := f.login("root", ownerPassword)
	var av adminView
	if code := owner.do("POST", "/api/v1/admins", adminCreate{Username: "watcher", Password: "short", Role: "viewer"}, nil); code != 400 {
		t.Fatalf("short password: %d", code)
	}
	if code := owner.do("POST", "/api/v1/admins", adminCreate{Username: "watcher", Password: "long-enough-pass", Role: "king"}, nil); code != 400 {
		t.Fatalf("bad role: %d", code)
	}
	if code := owner.do("POST", "/api/v1/admins", adminCreate{Username: "watcher", Password: "long-enough-pass", Role: "viewer"}, &av); code != 201 || av.Role != "viewer" {
		t.Fatalf("create %d %+v", code, av)
	}
	if code := owner.do("POST", "/api/v1/admins", adminCreate{Username: "WATCHER", Password: "long-enough-pass", Role: "viewer"}, nil); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	op := f.addAdmin("ops", "operator-password", store.RoleOperator)

	viewer := f.login("watcher", "long-enough-pass")
	if code := viewer.do("GET", "/api/v1/node/status", nil, nil); code != 200 {
		t.Fatalf("viewer read: %d", code)
	}
	for _, x := range []struct{ m, p string }{{"PUT", "/api/v1/steering"}, {"POST", "/api/v1/node/reload"},
		{"GET", "/api/v1/admins"}, {"GET", "/api/v1/audit"}} {
		if code := viewer.do(x.m, x.p, steeringView{}, nil); code != 403 {
			t.Errorf("viewer %s %s: %d", x.m, x.p, code)
		}
	}
	opc := f.login("ops", "operator-password")
	if code := opc.do("POST", "/api/v1/node/reload", nil, nil); code != 204 {
		t.Fatalf("operator reload: %d", code)
	}
	if code := opc.do("POST", "/api/v1/admins", adminCreate{Username: "x123", Password: "long-enough-pass", Role: "owner"}, nil); code != 403 {
		t.Fatalf("operator creating admin: %d", code)
	}

	var list []adminView
	owner.do("GET", "/api/v1/admins", nil, &list)
	if len(list) != 3 {
		t.Fatalf("admins %+v", list)
	}
	rootID := ""
	for _, a := range list {
		if a.Username == "root" {
			rootID = a.ID
			if a.LastLoginAt == nil {
				t.Fatal("last login not recorded")
			}
		}
	}
	var e errorView
	if code := owner.do("DELETE", "/api/v1/admins/"+rootID, nil, &e); code != 403 || e.Code != "last_owner" {
		t.Fatalf("delete last owner: %d %+v", code, e)
	}
	if code := owner.do("DELETE", "/api/v1/admins/"+op.ID, nil, nil); code != 204 {
		t.Fatalf("delete operator: %d", code)
	}
	if code := opc.do("GET", "/api/v1/node/status", nil, nil); code != 401 {
		t.Fatalf("deleted admin's session survived: %d", code)
	}
	if code := owner.do("DELETE", "/api/v1/admins/nope", nil, nil); code != 404 {
		t.Fatalf("delete missing: %d", code)
	}

	var page auditPageView
	if code := owner.do("GET", "/api/v1/audit?limit=2", nil, &page); code != 200 || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("audit page %d %+v", code, page)
	}
	if page.Items[0].Action != "admin.delete" || page.Items[0].Admin != "root" || page.Items[0].SourceIP != "127.0.0.1" {
		t.Fatalf("latest audit %+v", page.Items[0])
	}
	var page2 auditPageView
	owner.do("GET", "/api/v1/audit?limit=2&cursor="+page.NextCursor, nil, &page2)
	if len(page2.Items) == 0 || page2.Items[0].At.After(page.Items[1].At) {
		t.Fatalf("second page %+v", page2)
	}
	for _, q := range []string{"limit=0", "limit=201", "cursor=abc"} {
		if code := owner.do("GET", "/api/v1/audit?"+q, nil, nil); code != 400 {
			t.Errorf("audit %s: %d", q, code)
		}
	}
}

func TestTrafficSeries(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	now := time.Now()
	_ = f.store.AddTraffic(context.Background(), now.Truncate(time.Minute), []store.TrafficSample{
		{Scope: store.ScopeNode, BytesIn: 1000, BytesOut: 2000},
		{Scope: store.ScopePort(443), BytesIn: 5, BytesOut: 6},
	})
	var ts trafficSeriesView
	if code := c.do("GET", "/api/v1/stats/traffic?range=1h", nil, &ts); code != 200 || ts.StepSec != 60 || len(ts.Points) != 60 {
		t.Fatalf("1h: %d step %d points %d", code, ts.StepSec, len(ts.Points))
	}
	if last := ts.Points[len(ts.Points)-1]; last.BytesIn != 1000 || last.BytesOut != 2000 {
		t.Fatalf("latest point %+v", last)
	}
	c.do("GET", "/api/v1/stats/traffic?range=24h&port=443", nil, &ts)
	if ts.StepSec != 900 || ts.Points[len(ts.Points)-1].BytesOut != 6 {
		t.Fatalf("port series step %d last %+v", ts.StepSec, ts.Points[len(ts.Points)-1])
	}
	for _, q := range []string{"range=2y", "port=0", "port=x"} {
		if code := c.do("GET", "/api/v1/stats/traffic?"+q, nil, nil); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}
	// The sampler stores deltas between counter readings.
	sm := newTrafficSampler(f.node, f.store, f.srv.log)
	sm.sample(context.Background(), now)
	sm.last[store.ScopeNode] = [2]int64{-10, -10} // pretend the counters grew by 10
	sm.sample(context.Background(), now.Add(time.Minute))
	pts, _ := f.store.QueryTraffic(context.Background(), store.ScopeNode, now.Add(time.Minute).Truncate(time.Minute), now.Add(2*time.Minute), time.Minute)
	if pts[0].BytesIn != 10 {
		t.Fatalf("sampled delta %+v", pts)
	}
	if delta(100, 40) != 40 || delta(40, 100) != 60 {
		t.Fatal("delta")
	}
}

func TestWebSocket(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	u, _ := url.Parse(f.ts.URL)
	wsURL := "ws://" + u.Host + "/api/v1/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: c.hc})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ev eventView
	if err := json.Unmarshal(msg, &ev); err != nil || ev.Type != "status.tick" || ev.Data["nodeId"] != "iran-01" {
		t.Fatalf("first event %s %v", msg, err)
	}
	// A node event arrives too.
	c.do("POST", "/api/v1/node/reload", nil, nil)
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(msg, &ev)
		if ev.Type == "config.applied" {
			break
		}
	}

	// Without a session, or from another site, the upgrade is refused.
	if _, resp, err := websocket.Dial(ctx, wsURL, nil); err == nil || resp.StatusCode != 401 {
		t.Fatalf("anonymous ws: %v", err)
	}
	h := http.Header{"Origin": []string{"https://evil.example"}}
	if _, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: c.hc, HTTPHeader: h}); err == nil {
		t.Fatal("cross-origin ws accepted")
	}
}

func TestStaticPanel(t *testing.T) {
	f := newFixture(t)
	c := f.anon()
	get := func(p string) (*http.Response, string) {
		resp, err := c.hc.Get(f.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	for _, p := range []string{"/", "/peers", "/settings/security"} {
		resp, body := get(p)
		if resp.StatusCode != 200 || !strings.Contains(body, "<title>Marmot</title>") || resp.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: %d %q", p, resp.StatusCode, body)
		}
	}
	resp, body := get("/assets/app-1234.js")
	if resp.StatusCode != 200 || body != "console.log(1)" || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get("/assets/missing.js"); resp.StatusCode != 404 {
		t.Fatalf("missing asset: %d", resp.StatusCode)
	}
	if resp, _ := get("/../../etc/passwd"); resp.StatusCode != 200 {
		t.Fatalf("traversal attempt should get the app: %d", resp.StatusCode)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}

func TestAllowIPs(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	var doc configDocument
	c.do("GET", "/api/v1/config", nil, &doc)
	locked := strings.Replace(doc.TOML, "[api]", "[api]\nallow_ips = [\"10.9.9.0/24\"]", 1)
	if code := c.do("PUT", "/api/v1/config", configDocument{TOML: locked, Version: doc.Version}, nil); code != 200 {
		t.Fatalf("put: %d", code)
	}
	var e errorView
	if code := c.do("GET", "/api/v1/node/status", nil, &e); code != 403 || e.Code != "forbidden" {
		t.Fatalf("outside allow list: %d %+v", code, e)
	}
	if !ipAllowed("127.0.0.1", []string{"127.0.0.1"}) || !ipAllowed("10.0.0.5", []string{"10.0.0.0/8"}) || ipAllowed("junk", []string{"10.0.0.0/8"}) {
		t.Fatal("ipAllowed")
	}
}

func TestPeerIPv6PoolRoundTrip(t *testing.T) {
	f := newFixture(t)
	c := f.login("root", ownerPassword)
	other, _ := crypto.GenerateIdentity()
	peer := peerView{ID: "v6-peer", PublicKey: config.FormatPublicKey(other.PublicKey()),
		IPv6Pool:  []string{"2001:db8::10"},
		Endpoints: []endpointView{{Transport: "tls", Ports: []int{9443}, Direction: "outbound"}}}
	var pv peerView
	if code := c.do("POST", "/api/v1/peers", peer, &pv); code != 201 || len(pv.IPv6Pool) != 1 {
		t.Fatalf("create %d %+v", code, pv)
	}
	peer.Weight = 7
	if code := c.do("PUT", "/api/v1/peers/v6-peer", peer, &pv); code != 200 || len(pv.IPv6Pool) != 1 || pv.IPv6Pool[0] != "2001:db8::10" {
		t.Fatalf("update dropped ipv6Pool: %d %+v", code, pv)
	}
	if f.node.Config().Peers[0].IPv6Pool[0] != "2001:db8::10" {
		t.Fatal("ipv6_pool not in the applied config")
	}
}
