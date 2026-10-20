package config

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"marmot/internal/core"
)

var testKey = FormatPublicKey(make(ed25519.PublicKey, ed25519.PublicKeySize))

func validTOML() string {
	return `
[node]
id = "iran-01"
identity_key_file = "/etc/marmot/identity.key"

[steering]
tunneled_ports = [443, 8443, 2052, 2057]
vip_control_ports = [62050]
protocols = ["tcp", "udp"]
[steering.port_map]
2052 = 12052
[steering.port_protocols]
2057 = ["udp"]
[steering.port_peers]
443 = ["kharej-01"]

[panel_integration]
preserve_client_ip = "proxy_v2"

[[transport_listen]]
transport = "tls"
port = 9443
[[transport_listen]]
transport = "quic"
port_range = "40000-40010"

[[peers]]
id = "kharej-01"
public_key = "` + testKey + `"
weight = 5
ipv4_pool = ["198.51.100.1"]
ipv6_subnet = "2001:db8:2::/64"
  [[peers.endpoints]]
  transport = "tls"
  ports = [9443]
  options = { sni = "example.com", fingerprint = "chrome" }

[api]
listen = "0.0.0.0:7443"
tls_cert = "a.crt"
tls_key = "a.key"
`
}

func TestParseValid(t *testing.T) {
	l, err := Parse([]byte(validTOML()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := l.Config
	if c.Node.Role != DefaultRole || c.Session.StandbyPaths != DefaultStandbyPaths {
		t.Fatalf("defaults not applied: %+v", c.Node)
	}
	if c.Session.ResumeTimeout.D() != 30*time.Second {
		t.Fatalf("resume timeout %v", c.Session.ResumeTimeout.D())
	}
	if c.TransportListen[1].PortRange != (PortRange{40000, 40010}) {
		t.Fatalf("port range %+v", c.TransportListen[1].PortRange)
	}
	if got := c.Peers[0].Endpoints[0].Options["sni"]; got != "example.com" {
		t.Fatalf("options sni = %v", got)
	}
	if l.Version == "" || len(l.Version) != 16 {
		t.Fatalf("version %q", l.Version)
	}
}

func TestPortRules(t *testing.T) {
	l, err := Parse([]byte(validTOML()))
	if err != nil {
		t.Fatal(err)
	}
	rules := l.Config.Steering.PortRules()
	if len(rules) != 5 {
		t.Fatalf("got %d rules", len(rules))
	}
	byPort := map[uint16]PortRule{}
	for _, r := range rules {
		byPort[r.Port] = r
	}
	if r := byPort[2052]; r.TargetPort != 12052 || !r.HasProto(core.ProtoTCP) || !r.HasProto(core.ProtoUDP) {
		t.Fatalf("2052 rule %+v", r)
	}
	if r := byPort[2057]; r.HasProto(core.ProtoTCP) || !r.HasProto(core.ProtoUDP) {
		t.Fatalf("2057 rule %+v", r)
	}
	if r := byPort[62050]; r.Class != core.ClassVIP {
		t.Fatalf("62050 rule %+v", r)
	}
	if r := byPort[443]; len(r.Peers) != 1 || r.Peers[0] != "kharej-01" {
		t.Fatalf("443 rule %+v", r)
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantMsg string
	}{
		{"unknown key", func(s string) string { return s + "\n[bogus]\nx=1\n" }, "unknown key"},
		{"ssh tunneled", func(s string) string {
			return strings.Replace(s, "tunneled_ports = [443,", "tunneled_ports = [22, 443,", 1)
		}, "protected"},
		{"duplicate port", func(s string) string {
			return strings.Replace(s, "vip_control_ports = [62050]", "vip_control_ports = [443]", 1)
		}, "more than once"},
		{"listen collides with user port", func(s string) string {
			return strings.Replace(s, "port = 9443\n[[transport_listen]]", "port = 8443\n[[transport_listen]]", 1)
		}, "collides"},
		{"api on tunneled port", func(s string) string {
			return strings.Replace(s, `listen = "0.0.0.0:7443"`, `listen = "0.0.0.0:443"`, 1)
		}, "management port"},
		{"bad public key", func(s string) string { return strings.Replace(s, testKey, "ed25519:xxx", 1) }, "public key"},
		{"peer is self", func(s string) string { return strings.Replace(s, `id = "kharej-01"`, `id = "iran-01"`, 1) }, "this node"},
		{"bad role", func(s string) string { return strings.Replace(s, "[node]\n", "[node]\nrole = \"boss\"\n", 1) }, "node.role"},
		{"port_map unknown port", func(s string) string { return strings.Replace(s, "2052 = 12052", "9999 = 1", 1) }, "not a tunneled"},
		{"unknown port peer", func(s string) string { return strings.Replace(s, `443 = ["kharej-01"]`, `443 = ["ghost"]`, 1) }, "unknown peer"},
		{"bad ipv4", func(s string) string { return strings.Replace(s, `"198.51.100.1"`, `"2001:db8::1"`, 1) }, "IPv4"},
		{"small subnet", func(s string) string { return strings.Replace(s, "2001:db8:2::/64", "2001:db8:2::/96", 1) }, "/64"},
		{"bad port range", func(s string) string { return strings.Replace(s, "40000-40010", "40010-40000", 1) }, "port range"},
		{"endpoint without ports", func(s string) string { return strings.Replace(s, "  ports = [9443]\n", "", 1) }, "exactly one"},
		{"bad toml", func(string) string { return "[[[" }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.mutate(validTOML())))
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v, want *ValidationError", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantMsg)
			}
		})
	}
}

func TestUnits(t *testing.T) {
	var b ByteSize
	for in, want := range map[string]int64{"25MiB": 25 << 20, "4KB": 4000, "10": 10, "1 GiB": 1 << 30} {
		if err := b.UnmarshalText([]byte(in)); err != nil || int64(b) != want {
			t.Errorf("ByteSize(%q) = %d, %v", in, b, err)
		}
	}
	for _, in := range []string{"", "-1MiB", "x", "99999999999GiB"} {
		if err := b.UnmarshalText([]byte(in)); err == nil {
			t.Errorf("ByteSize(%q) should fail", in)
		}
	}
	var d Duration
	if err := d.UnmarshalText([]byte("-1s")); err == nil {
		t.Error("negative duration accepted")
	}
	var r PortRange
	if err := r.UnmarshalText([]byte("10-20")); err != nil || !r.Contains(15) || r.Contains(21) {
		t.Errorf("PortRange: %+v %v", r, err)
	}
	if txt, _ := r.MarshalText(); string(txt) != "10-20" {
		t.Errorf("PortRange.MarshalText = %s", txt)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(validTOML()))
	f.Add([]byte("[node]\nid='a'"))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Parse(data)
		if err == nil && l.Config == nil {
			t.Fatal("nil config without error")
		}
	})
}

func TestIPv6Pool(t *testing.T) {
	base := validTOML()
	ok := strings.Replace(base, `ipv4_pool = ["198.51.100.1"]`, `ipv4_pool = ["198.51.100.1"]
ipv6_pool = ["2001:db8:2::10", "2001:db8:2::11"]`, 1)
	l, err := Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Config.Peers[0].IPv6Pool) != 2 {
		t.Fatalf("pool %v", l.Config.Peers[0].IPv6Pool)
	}
	for _, bad := range []string{`"198.51.100.9"`, `"::ffff:192.0.2.1"`, `"2001:db8::1", "2001:db8::1"`, `"fe80::1%eth0"`} {
		cfg := strings.Replace(base, `ipv4_pool = ["198.51.100.1"]`, `ipv4_pool = ["198.51.100.1"]
ipv6_pool = [`+bad+`]`, 1)
		if _, err := Parse([]byte(cfg)); err == nil {
			t.Errorf("ipv6_pool [%s] accepted", bad)
		}
	}
	// A peer reachable only over IPv6 is valid.
	if !strings.Contains(base, "ipv4_pool = [\"198.51.100.1\"]\nipv6_subnet") || !strings.Contains(base, "[api]") {
		t.Fatal("fixture changed; the replacements below would test nothing")
	}
	v6only := strings.Replace(base, `ipv4_pool = ["198.51.100.1"]
ipv6_subnet = "2001:db8:2::/64"`, `ipv6_pool = ["2001:db8:2::10"]`, 1)
	if _, err := Parse([]byte(v6only)); err != nil {
		t.Fatalf("IPv6-only peer: %v", err)
	}
	local := strings.Replace(base, "[api]", "[local]\nipv6_pool = [\"2001:db8:1::5\"]\n[api]", 1)
	if _, err := Parse([]byte(local)); err != nil {
		t.Fatalf("local ipv6_pool: %v", err)
	}
}
