package node

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/frame"
)

// relayTriangle is ARCHITECTURE §3.3 with the direct route blocked:
//
//	user ──► iran ══ x ══ kharej          (direct route: nothing listens)
//	         iran ══ tls ══► relay ══ tls ══► kharej ──► panel
type relayTriangle struct {
	iran, relay, kharej *Node
	userPort            uint16
	kharejInter         uint16 // kharej's real listener
	blockedPort         uint16 // what iran dials directly
	relayTOML           string
	relayID             *crypto.Identity
}

func newRelayTriangle(t *testing.T, allowTransit bool, kharejDirect bool) *relayTriangle {
	t.Helper()
	ids := make([]*crypto.Identity, 3)
	for i := range ids {
		var err error
		if ids[i], err = crypto.GenerateIdentity(); err != nil {
			t.Fatal(err)
		}
	}
	iranID, relayID, kharejID := ids[0], ids[1], ids[2]
	key := func(id *crypto.Identity) string { return config.FormatPublicKey(id.PublicKey()) }
	panel := echoServer(t)
	rt := &relayTriangle{userPort: freePort(t), kharejInter: freePort(t), blockedPort: freePort(t), relayID: relayID}
	relayInter := freePort(t)
	direct := rt.blockedPort
	if kharejDirect {
		direct = rt.kharejInter
	}

	iranTOML := fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[steering]
tunneled_ports = [%d]
protocols = ["tcp"]
[steering.port_map]
%d = %d
[steering.port_peers]
"%d" = ["kharej-01"]
[session]
probe_interval = "200ms"
standby_paths = 1
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tcp"
  ports = [%d]
[[peers]]
id = "relay-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]
[api]
listen = "127.0.0.1:%d"
`, rt.userPort, rt.userPort, panel, rt.userPort, key(kharejID), direct, key(relayID), relayInter, freePort(t))

	rt.relayTOML = fmt.Sprintf(`
[node]
id = "relay-01"
identity_key_file = "unused"
[[transport_listen]]
transport = "tls"
port = %d
[relay]
allow_transit = %t
[session]
probe_interval = "200ms"
[[peers]]
id = "iran-01"
public_key = %q
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tcp"
  ports = [%d]
[api]
listen = "127.0.0.1:%d"
`, relayInter, allowTransit, key(iranID), key(kharejID), rt.kharejInter, freePort(t))

	kharejTOML := fmt.Sprintf(`
[node]
id = "kharej-01"
identity_key_file = "unused"
[[transport_listen]]
transport = "tcp"
port = %d
[session]
probe_interval = "200ms"
[[peers]]
id = "iran-01"
public_key = %q
[[peers]]
id = "relay-01"
public_key = %q
[api]
listen = "127.0.0.1:%d"
`, rt.kharejInter, key(iranID), key(relayID), freePort(t))

	start := func(toml string, id *crypto.Identity) *Node {
		n, err := New(parse(t, toml), id, Options{Version: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Start(); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rt.kharej = start(kharejTOML, kharejID)
	rt.relay = start(rt.relayTOML, relayID)
	rt.iran = start(iranTOML, iranID)
	t.Cleanup(func() {
		_ = rt.iran.Stop()
		_ = rt.relay.Stop()
		_ = rt.kharej.Stop()
	})
	return rt
}

func waitPeerState(t *testing.T, n *Node, peer, state string, within time.Duration) PeerStatus {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		for _, p := range n.Snapshot().Peers {
			if string(p.ID) == peer && p.State == state {
				return p
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer %s never became %s: %+v", peer, state, n.Snapshot().Peers)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRelayRouting(t *testing.T) {
	rt := newRelayTriangle(t, true, false)
	p := waitPeerState(t, rt.iran, "kharej-01", PeerRelayed, 15*time.Second)
	var active string
	for _, path := range p.Sessions[0].Paths {
		if path.Active {
			active = path.Meta.Remote
		}
	}
	if active != relayMetaPrefix+"relay-01" {
		t.Fatalf("active path %q, want through relay-01", active)
	}

	c, err := userRoundTrip(t, rt.userPort, "through the relay")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	if tr := rt.relay.Snapshot().Transit; tr.Active == 0 {
		t.Fatalf("relay reports no transit: %+v", tr)
	}
	// The relay forwards ciphertext only: its forwarder saw no user stream.
	if fs := rt.relay.Snapshot().Forwarder; fs.Streams != 0 {
		t.Fatalf("relay delivered user streams itself: %+v", fs)
	}
	// kharej sees iran as a peer reached through the relay.
	waitPeerState(t, rt.kharej, "iran-01", PeerRelayed, 5*time.Second)
}

// When the direct route starts working, the session moves off the relay
// make-before-break and the user connection survives.
func TestRelayToDirect(t *testing.T) {
	rt := newRelayTriangle(t, true, false)
	waitPeerState(t, rt.iran, "kharej-01", PeerRelayed, 15*time.Second)
	c, err := userRoundTrip(t, rt.userPort, "before")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Unblock: forward the blocked port to kharej's listener.
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", rt.blockedPort))
	if err != nil {
		t.Skipf("port %d taken: %v", rt.blockedPort, err)
	}
	defer l.Close()
	go func() {
		for {
			a, err := l.Accept()
			if err != nil {
				return
			}
			b, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", rt.kharejInter))
			if err != nil {
				_ = a.Close()
				continue
			}
			go func() { _, _ = io.Copy(b, a); _ = b.Close() }()
			go func() { _, _ = io.Copy(a, b); _ = a.Close() }()
		}
	}()
	// Quarantine of the direct route grows to a few seconds by now.
	waitPeerState(t, rt.iran, "kharej-01", PeerUp, 40*time.Second)

	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "after" {
		t.Fatalf("connection did not survive the move: %q %v", got, err)
	}
}

func TestRelayTransitDenied(t *testing.T) {
	rt := newRelayTriangle(t, false, false)
	// The relay session comes up, but the relay refuses transit, so kharej
	// stays unreachable.
	waitPeerState(t, rt.iran, "relay-01", PeerUp, 10*time.Second)
	time.Sleep(2 * time.Second)
	for _, p := range rt.iran.Snapshot().Peers {
		if p.ID == "kharej-01" && p.State != PeerDown {
			t.Fatalf("kharej reachable without transit: %+v", p)
		}
	}
	if tr := rt.relay.Snapshot().Transit; tr.Active != 0 {
		t.Fatalf("transit with allow_transit = false: %+v", tr)
	}
}

func TestTransitCheck(t *testing.T) {
	rt := newRelayTriangle(t, true, true)
	waitPeerState(t, rt.relay, "kharej-01", PeerUp, 10*time.Second)
	cases := []struct {
		from  string
		route []string
		want  byte
	}{
		{"iran-01", []string{"kharej-01"}, frame.ReplyOK},
		{"iran-01", []string{"iran-01"}, frame.ReplyDenied},        // back to the sender
		{"iran-01", []string{"relay-01"}, frame.ReplyDenied},       // to itself
		{"iran-01", []string{"kharej-01", "x"}, frame.ReplyDenied}, // over max_hops
		{"iran-01", []string{"nobody"}, frame.ReplyUnreachable},    // no session
		{"kharej-01", []string{"kharej-01"}, frame.ReplyDenied},    // a loop
	}
	for _, c := range cases {
		got, _ := rt.relay.transitCheck(core.NodeID(c.from), nodeIDs(c.route))
		if got != c.want {
			t.Errorf("transit %s via %v = %d, want %d", c.from, c.route, got, c.want)
		}
	}
	// max_hops = 3 lets a two-hop route through.
	cfg := parse(t, strings.Replace(rt.relayTOML, "allow_transit = true", "allow_transit = true\nmax_hops = 3", 1))
	if err := rt.relay.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	waitPeerState(t, rt.relay, "kharej-01", PeerUp, 10*time.Second) // links restart on [relay] changes
	if got, _ := rt.relay.transitCheck("iran-01", nodeIDs([]string{"kharej-01", "x"})); got != frame.ReplyOK {
		t.Errorf("two-hop route under max_hops 3 = %d, want OK", got)
	}
}

func nodeIDs(ss []string) []core.NodeID {
	out := make([]core.NodeID, len(ss))
	for i, s := range ss {
		out[i] = core.NodeID(s)
	}
	return out
}

// A session runs over each HTTP-based transport, with and without TLS.
func TestTransportsEndToEnd(t *testing.T) {
	for _, tr := range []struct{ name, opts string }{
		{"ws", `{ path = "/edge", sni = "cdn.example.com" }`},
		{"ws", `{ tls = false }`},
		{"grpc", `{ service = "edge.Stream", sni = "cdn.example.com" }`},
		{"grpc", `{ tls = false }`},
	} {
		t.Run(tr.name, func(t *testing.T) {
			ids := make([]*crypto.Identity, 2)
			for i := range ids {
				var err error
				if ids[i], err = crypto.GenerateIdentity(); err != nil {
					t.Fatal(err)
				}
			}
			panel, user, inter := echoServer(t), freePort(t), freePort(t)
			kharej := fmt.Sprintf(`
[node]
id = "kharej-01"
identity_key_file = "unused"
[[transport_listen]]
transport = %q
port = %d
options = %s
[[peers]]
id = "iran-01"
public_key = %q
[api]
listen = "127.0.0.1:%d"
`, tr.name, inter, tr.opts, config.FormatPublicKey(ids[0].PublicKey()), freePort(t))
			iran := fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[steering]
tunneled_ports = [%d]
protocols = ["tcp"]
[steering.port_map]
%d = %d
[session]
probe_interval = "200ms"
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = %q
  ports = [%d]
  options = %s
[api]
listen = "127.0.0.1:%d"
`, user, user, panel, config.FormatPublicKey(ids[1].PublicKey()), tr.name, inter, tr.opts, freePort(t))
			for _, c := range []struct {
				toml string
				id   *crypto.Identity
			}{{kharej, ids[1]}, {iran, ids[0]}} {
				n, err := New(parse(t, c.toml), c.id, Options{Version: "test"})
				if err != nil {
					t.Fatal(err)
				}
				if err := n.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = n.Stop() })
				if c.id == ids[0] {
					p := waitPeerState(t, n, "kharej-01", PeerUp, 10*time.Second)
					if got := p.Sessions[0].Paths[0].Meta.Transport; got != tr.name {
						t.Fatalf("path transport %q", got)
					}
				}
			}
			c, err := userRoundTrip(t, user, "over "+tr.name)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
		})
	}
}

// With IPv4 and IPv6 addresses for a peer, the standby path takes the
// other family than the active one (ADR-0011 diversity).
func TestDualStackStandby(t *testing.T) {
	if l, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	} else {
		_ = l.Close()
	}
	ids := make([]*crypto.Identity, 2)
	for i := range ids {
		var err error
		if ids[i], err = crypto.GenerateIdentity(); err != nil {
			t.Fatal(err)
		}
	}
	inter := freePort(t)
	kharej := fmt.Sprintf(`
[node]
id = "kharej-01"
identity_key_file = "unused"
[[transport_listen]]
transport = "tcp"
port = %d
[[peers]]
id = "iran-01"
public_key = %q
[api]
listen = "127.0.0.1:%d"
`, inter, config.FormatPublicKey(ids[0].PublicKey()), freePort(t))
	iran := fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[session]
probe_interval = "200ms"
standby_paths = 1
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
ipv6_pool = ["::1"]
  [[peers.endpoints]]
  transport = "tcp"
  ports = [%d]
[api]
listen = "127.0.0.1:%d"
`, config.FormatPublicKey(ids[1].PublicKey()), inter, freePort(t))
	var nodes []*Node
	for _, c := range []struct {
		toml string
		id   *crypto.Identity
	}{{kharej, ids[1]}, {iran, ids[0]}} {
		n, err := New(parse(t, c.toml), c.id, Options{Version: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = n.Stop() })
		nodes = append(nodes, n)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		p := nodes[1].Snapshot().Peers[0]
		if len(p.Sessions) == 1 && len(p.Sessions[0].Paths) == 2 {
			paths := p.Sessions[0].Paths
			a := routeOf(paths[0].Meta).Remote.Addr()
			b := routeOf(paths[1].Meta).Remote.Addr()
			if a.Is4() == b.Is4() {
				t.Fatalf("both paths on one family: %v %v", paths[0].Meta, paths[1].Meta)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("standby not joined: %+v", p)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
