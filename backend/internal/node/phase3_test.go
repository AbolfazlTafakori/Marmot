package node

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"marmot/internal/config"
	"marmot/internal/controller"
	"marmot/internal/crypto"
	"marmot/internal/mesh"
	"marmot/internal/proxyproto"
)

// twoNodes starts iran (dialer) and kharej with a fake panel behind kharej
// and returns iran's user port.
func twoNodes(t *testing.T, iranExtra, endpoints, kharejExtra, listen string) (*relayFixture, uint16) {
	t.Helper()
	f := &relayFixture{t: t, panelHeaders: make(chan proxyproto.Header, 16)}
	var err error
	if f.iranID, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	if f.kharejID, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	f.userPort = freePort(t)
	f.startPanel()
	f.iranTOML = fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[steering]
tunneled_ports = [%d]
[steering.port_map]
%d = %d
%s
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
%s
[api]
listen = "127.0.0.1:%d"
`, f.userPort, f.userPort, f.panelPort, iranExtra, config.FormatPublicKey(f.kharejID.PublicKey()), endpoints, freePort(t))
	f.kharejTOML = fmt.Sprintf(`
[node]
id = "kharej-01"
identity_key_file = "unused"
[panel_integration]
preserve_client_ip = "proxy_v2"
%s
%s
[[peers]]
id = "iran-01"
public_key = %q
[api]
listen = "127.0.0.1:%d"
`, kharejExtra, listen, config.FormatPublicKey(f.iranID.PublicKey()), freePort(t))
	f.kharej = f.start(f.kharejTOML, f.kharejID)
	f.iran = f.start(f.iranTOML, f.iranID)
	t.Cleanup(func() {
		_ = f.iran.Stop()
		_ = f.kharej.Stop()
	})
	f.waitPeerUp(f.iran, "kharej-01")
	return f, f.userPort
}

func onlySession(t *testing.T, n *Node) SessionStatus {
	t.Helper()
	ss := n.Snapshot().Peers[0].Sessions
	if len(ss) != 1 {
		t.Fatalf("%d sessions, want 1", len(ss))
	}
	return ss[0]
}

func TestQUICLinkRunsV2OnDatagramPaths(t *testing.T) {
	q1, q2 := freeUDPPort(t), freeUDPPort(t)
	f, port := twoNodes(t, `[session]
probe_interval = "200ms"
standby_paths = 1
[fec]
mode = "fixed"
data_shards = 4
max_parity_shards = 2`, fmt.Sprintf(`  [[peers.endpoints]]
  transport = "quic"
  ports = [%d, %d]`, q1, q2), `[fec]
mode = "fixed"
data_shards = 4
max_parity_shards = 2`, fmt.Sprintf(`[[transport_listen]]
transport = "quic"
port = %d
[[transport_listen]]
transport = "quic"
port = %d`, q1, q2))
	c, err := userRoundTrip(t, port, "hello over quic datagrams")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	<-f.panelHeaders
	waitUntil(t, func() bool { return len(onlySession(t, f.iran).Paths) == 2 })
	ss := onlySession(t, f.iran)
	if ss.Version != 2 || ss.FECData != 4 || ss.FECParity != 2 {
		t.Fatalf("session version %d fec %d+%d", ss.Version, ss.FECData, ss.FECParity)
	}
	for _, p := range ss.Paths {
		if !p.Datagram || p.Meta.Transport != "quic" {
			t.Fatalf("path %+v is not a quic datagram path", p.Meta)
		}
	}
}

func TestSessionVersionOneTalksToTwo(t *testing.T) {
	tp := freePort(t)
	f, port := twoNodes(t, `[session]
version = 1`, fmt.Sprintf(`  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]`, tp), "", fmt.Sprintf(`[[transport_listen]]
transport = "tls"
port = %d`, tp))
	c, err := userRoundTrip(t, port, "v1 still works")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if v := onlySession(t, f.iran).Version; v != 1 {
		t.Fatalf("version %d, want 1: iran offered only v1", v)
	}
	waitUntil(t, func() bool {
		ss := f.kharej.Snapshot().Peers[0].Sessions
		return len(ss) == 1 && ss[0].Version == 1
	})
}

func TestQUICPortRangeListener(t *testing.T) {
	lo := freeUDPPort(t)
	f, _ := twoNodes(t, "", fmt.Sprintf(`  [[peers.endpoints]]
  transport = "quic"
  port_range = "%d-%d"`, lo, lo+2), "", fmt.Sprintf(`[[transport_listen]]
transport = "quic"
port_range = "%d-%d"`, lo, lo+2))
	if n := len(f.kharej.Snapshot().Listeners); n != 3 {
		t.Fatalf("%d listeners for a range of 3 ports", n)
	}
}

func TestControlTickRatesPaths(t *testing.T) {
	tp, q := freePort(t), freeUDPPort(t)
	f, port := twoNodes(t, `[session]
probe_interval = "200ms"
standby_paths = 1`, fmt.Sprintf(`  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]
  [[peers.endpoints]]
  transport = "quic"
  ports = [%d]`, tp, q), "", fmt.Sprintf(`[[transport_listen]]
transport = "tls"
port = %d
[[transport_listen]]
transport = "quic"
port = %d`, tp, q))
	c, err := userRoundTrip(t, port, "rate me")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	waitUntil(t, func() bool { return len(onlySession(t, f.iran).Paths) == 2 })
	ctl := controller.New()
	now := time.Now()
	for i := range 3 {
		f.iran.controlTick(ctl, now.Add(time.Duration(i)*time.Second))
	}
	for _, p := range onlySession(t, f.iran).Paths {
		if !p.Scored {
			t.Fatalf("path %s not rated by the controller", p.Meta)
		}
	}
}

func TestPreferenceAndHealthWeight(t *testing.T) {
	now := time.Unix(1000, 0)
	quic := mesh.Candidate{Transport: "quic"}
	tls := mesh.Candidate{Transport: "tls"}
	quic.Remote = netip.MustParseAddrPort("192.0.2.1:443")
	tls.Remote = netip.MustParseAddrPort("192.0.2.1:443")
	pref := preference(now, map[string]time.Time{"tls": now.Add(time.Minute)},
		map[string]float64{"quic|192.0.2.1:443": 30})
	if pref(quic) != 30 || pref(tls) != prefUnmeasured+prefDemoted {
		t.Fatalf("quic %d tls %d", pref(quic), pref(tls))
	}
	expired := preference(now, map[string]time.Time{"tls": now}, nil)
	if expired(tls) != prefUnmeasured {
		t.Fatal("an expired demotion still counts")
	}
	if w := healthWeight(5, 0.5, true); w != 25 {
		t.Fatalf("weight %d", w)
	}
	if w := healthWeight(3, 0, false); w != 30 {
		t.Fatalf("unknown health weight %d", w)
	}
	if w := healthWeight(1, 0.01, true); w != 1 {
		t.Fatalf("weight floor %d", w)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
