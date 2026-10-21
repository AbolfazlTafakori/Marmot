package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"marmot/internal/config"
	"marmot/internal/crypto"
	"marmot/internal/mesh"
	"marmot/internal/proxyproto"

	_ "marmot/internal/transport/udp"
)

// Reverse (ADR-0017): iran lists kharej's endpoint as inbound, so iran
// never dials; kharej dials iran, and iran's users still reach the panel
// behind kharej through that inbound session.
func TestInboundEndpointIsNotDialed(t *testing.T) {
	f := &relayFixture{t: t, panelHeaders: make(chan proxyproto.Header, 16)}
	f.iranID, _ = crypto.GenerateIdentity()
	f.kharejID, _ = crypto.GenerateIdentity()
	f.userPort = freePort(t)
	f.startPanel()
	iranListen, kharejListen := freePort(t), freePort(t)
	iranTOML := fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[steering]
tunneled_ports = [%d]
[steering.port_map]
%d = %d
[[transport_listen]]
transport = "tls"
port = %d
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]
  direction = "inbound"
[api]
listen = "127.0.0.1:%d"
`, f.userPort, f.userPort, f.panelPort, iranListen, config.FormatPublicKey(f.kharejID.PublicKey()), kharejListen, freePort(t))
	kharejTOML := fmt.Sprintf(`
[node]
id = "kharej-01"
identity_key_file = "unused"
[panel_integration]
preserve_client_ip = "proxy_v2"
[[transport_listen]]
transport = "tls"
port = %d
[[peers]]
id = "iran-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]
[api]
listen = "127.0.0.1:%d"
`, kharejListen, config.FormatPublicKey(f.iranID.PublicKey()), iranListen, freePort(t))
	f.iran = f.start(iranTOML, f.iranID)
	f.kharej = f.start(kharejTOML, f.kharejID)
	t.Cleanup(func() { _ = f.iran.Stop(); _ = f.kharej.Stop() })
	f.waitPeerUp(f.iran, "kharej-01")
	for _, s := range f.iran.Snapshot().Peers[0].Sessions {
		if s.Outbound {
			t.Fatal("iran dialed an inbound endpoint")
		}
	}
	c, err := userRoundTrip(t, f.userPort, "over the reverse session")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestRoutesRotateWithEpochs(t *testing.T) {
	c := parse(t, fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[local]
ipv6_subnet = "2001:db8:1:1::/64"
ipv6_rotation = { enabled = true, epoch = "60s", active = 2 }
[[peers]]
id = "kharej-01"
public_key = %q
ipv6_subnet = "2001:db8:2:2::/64"
  [[peers.endpoints]]
  transport = "tls"
  ports = [443]
[api]
listen = "127.0.0.1:1"
`, config.FormatPublicKey(mustKey(t))))
	r, _ := routesFor(c, c.Peers[0])
	if !r.dynamic {
		t.Fatal("rotation must rebuild routes")
	}
	now := time.Unix(6000, 0)
	cands := r.build(now)
	locals := mesh.RotatingAddrs(netip.MustParsePrefix("2001:db8:1:1::/64"), "iran-01", mesh.Epoch(now, time.Minute), 2)
	remotes := mesh.RotatingAddrs(netip.MustParsePrefix("2001:db8:2:2::/64"), "kharej-01", mesh.Epoch(now, time.Minute), 2)
	if len(cands) != 4 {
		t.Fatalf("%d candidates, want 2 sources x 2 destinations", len(cands))
	}
	for _, cd := range cands {
		if !contains(locals, cd.Local) || !contains(remotes, cd.Remote.Addr()) {
			t.Fatalf("candidate %v not from this epoch", cd)
		}
	}
	if r.stale(now, locals[0], remotes[0]) {
		t.Fatal("current addresses reported stale")
	}
	later := now.Add(time.Minute)
	if !r.stale(later, locals[0], netip.MustParseAddr("2001:db8:9::1")) || !r.stale(later, netip.MustParseAddr("192.0.2.1"), remotes[0]) {
		t.Fatal("addresses of the last epoch not reported stale")
	}
	if r.stale(later, netip.MustParseAddr("2001:db8:7::1"), netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("addresses outside the rotating subnets reported stale")
	}
}

func mustKey(t *testing.T) []byte {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id.PublicKey()
}

// Port hopping (ADR-0018): a path older than its endpoint's hop interval
// is replaced by one on another port, make-before-break.
func TestPortHopReplacesPath(t *testing.T) {
	lo := freeUDPPort(t)
	f, port := twoNodes(t, `[session]
probe_interval = "200ms"
standby_paths = 0`, fmt.Sprintf(`  [[peers.endpoints]]
  transport = "udp"
  port_range = "%d-%d"
  hop_interval = "10s"`, lo, lo+3), "", fmt.Sprintf(`[[transport_listen]]
transport = "udp"
port_range = "%d-%d"`, lo, lo+3))
	c, err := userRoundTrip(t, port, "before the hop")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-f.panelHeaders
	f.iran.mu.RLock()
	l := f.iran.links["kharej-01"]
	f.iran.mu.RUnlock()
	s := l.session()
	before := s.Stats().Paths[0]
	l.refreshPaths(context.Background(), s, time.Now().Add(11*time.Second))
	waitUntil(t, func() bool {
		for _, p := range s.Stats().Paths {
			if p.ID != before.ID && !p.Draining {
				return true
			}
		}
		return false
	})
	waitUntil(t, func() bool {
		for _, p := range s.Stats().Paths {
			if p.ID == before.ID {
				return false
			}
		}
		return true
	})
	// The user connection opened before the hop still works.
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := c.Read(got); err != nil || string(got) != "after" {
		t.Fatalf("after the hop: %q %v", got, err)
	}
}

func TestRotationNeedsLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("supported here")
	}
	id, _ := crypto.GenerateIdentity()
	n, err := New(parse(t, fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[local]
ipv6_subnet = "2001:db8:1:1::/64"
ipv6_rotation = { enabled = true }
[api]
listen = "127.0.0.1:%d"
`, freePort(t))), id, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); !errors.Is(err, ErrRotationUnsupported) {
		t.Fatalf("start: %v", err)
	}
}

// A session left with two paths on one route (the other routes were in
// quarantine when it filled up) gets the repeat replaced by a free,
// different route.
func TestDiversifyReplacesRepeatedRoute(t *testing.T) {
	tp, up := freePort(t), freeUDPPort(t)
	f, port := twoNodes(t, `[session]
probe_interval = "200ms"
standby_paths = 1`, fmt.Sprintf(`  [[peers.endpoints]]
  transport = "udp"
  ports = [%d]
  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]`, up, tp), "", fmt.Sprintf(`[[transport_listen]]
transport = "udp"
port = %d
[[transport_listen]]
transport = "tls"
port = %d`, up, tp))
	c, err := userRoundTrip(t, port, "x")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	f.iran.mu.RLock()
	l := f.iran.links["kharej-01"]
	f.iran.mu.RUnlock()
	s := l.session()
	waitUntil(t, func() bool { return len(s.Stats().Paths) == 2 })
	// Retire the tls path and add a second udp one: a repeated route.
	var udpCand mesh.Candidate
	for _, cd := range l.routes.build(time.Now()) {
		if cd.Transport == "udp" {
			udpCand = cd
		}
	}
	for _, p := range s.Stats().Paths {
		if p.Meta.Transport == "tls" {
			s.(retirer).Retire(p.ID)
		}
	}
	if err := l.join(context.Background(), s, udpCand, false); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool {
		n := 0
		for _, p := range s.Stats().Paths {
			if p.Meta.Transport == "udp" && !p.Draining {
				n++
			}
		}
		return n == 2
	})
	l.diversify(context.Background(), s)
	waitUntil(t, func() bool {
		tls, udp := 0, 0
		for _, p := range s.Stats().Paths {
			switch {
			case p.Draining:
			case p.Meta.Transport == "tls":
				tls++
			case p.Meta.Transport == "udp":
				udp++
			}
		}
		return tls == 1 && udp == 1
	})
}
