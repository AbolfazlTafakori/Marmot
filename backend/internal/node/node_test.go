package node

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"marmot/internal/config"
	"marmot/internal/crypto"
	"marmot/internal/proxyproto"

	_ "marmot/internal/transport/grpc"
	_ "marmot/internal/transport/quic"
	_ "marmot/internal/transport/tcp"
	_ "marmot/internal/transport/tls"
	_ "marmot/internal/transport/ws"
)

// The relay-mode scenario of ARCHITECTURE §3.1 inside one process:
//
//	user ──► iran :userPort ══ tls ══► kharej ──PROXY v2──► panel :panelPort
type relayFixture struct {
	t                    *testing.T
	iranID, kharejID     *crypto.Identity
	userPort, interPort  uint16
	quicPort             uint16
	panelPort            uint16
	panelHeaders         chan proxyproto.Header
	iran, kharej         *Node
	iranTOML, kharejTOML string
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

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func parse(t *testing.T, s string) *config.Config {
	t.Helper()
	l, err := config.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return l.Config
}

func newRelayFixture(t *testing.T) *relayFixture {
	f := &relayFixture{t: t, panelHeaders: make(chan proxyproto.Header, 16)}
	var err error
	if f.iranID, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	if f.kharejID, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	f.userPort, f.interPort, f.quicPort = freePort(t), freePort(t), freeUDPPort(t)
	f.startPanel()

	f.iranTOML = fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[steering]
tunneled_ports = [%d]
protocols = ["tcp", "udp"]
[steering.port_map]
%d = %d
[session]
probe_interval = "200ms"
standby_paths = 1
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]
  options = { sni = "cdn.example.com", fingerprint = "chrome" }
  [[peers.endpoints]]
  transport = "quic"
  ports = [%d]
[api]
listen = "127.0.0.1:%d"
`, f.userPort, f.userPort, f.panelPort, config.FormatPublicKey(f.kharejID.PublicKey()), f.interPort, f.quicPort, freePort(t))

	f.kharejTOML = fmt.Sprintf(`
[node]
id = "kharej-01"
identity_key_file = "unused"
[panel_integration]
preserve_client_ip = "proxy_v2"
[[transport_listen]]
transport = "tls"
port = %d
[[transport_listen]]
transport = "quic"
port = %d
[[peers]]
id = "iran-01"
public_key = %q
[api]
listen = "127.0.0.1:%d"
`, f.interPort, f.quicPort, config.FormatPublicKey(f.iranID.PublicKey()), freePort(t))

	f.kharej = f.start(f.kharejTOML, f.kharejID)
	f.iran = f.start(f.iranTOML, f.iranID)
	t.Cleanup(func() {
		_ = f.iran.Stop()
		_ = f.kharej.Stop()
	})
	return f
}

func (f *relayFixture) start(toml string, id *crypto.Identity) *Node {
	n, err := New(parse(f.t, toml), id, Options{Version: "test"})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// startPanel runs a fake panel inbound: TCP that expects PROXY v2 then
// echoes, and UDP that echoes, on the same port.
func (f *relayFixture) startPanel() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	f.panelPort = uint16(l.Addr().(*net.TCPAddr).Port)
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(f.panelPort)})
	if err != nil {
		f.t.Skipf("udp port %d taken: %v", f.panelPort, err)
	}
	f.t.Cleanup(func() {
		_ = l.Close()
		_ = uc.Close()
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				h, err := proxyproto.ReadHeader(c)
				if err != nil {
					return
				}
				f.panelHeaders <- h
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(buf[:n], from)
		}
	}()
}

func (f *relayFixture) waitPeerUp(n *Node, peer string) {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, p := range n.Snapshot().Peers {
			if string(p.ID) == peer && p.State == PeerUp {
				return
			}
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("peer %s never came up: %+v", peer, n.Snapshot().Peers)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func userRoundTrip(t *testing.T, port uint16, msg string) (net.Conn, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		c.Close()
		return nil, err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		c.Close()
		return nil, err
	}
	if string(got) != msg {
		c.Close()
		return nil, fmt.Errorf("echo %q", got)
	}
	return c, nil
}

func TestRelayModeEndToEnd(t *testing.T) {
	f := newRelayFixture(t)
	f.waitPeerUp(f.iran, "kharej-01")
	f.waitPeerUp(f.kharej, "iran-01")

	c, err := userRoundTrip(t, f.userPort, "vless handshake bytes")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := <-f.panelHeaders
	userAddr := netip.MustParseAddrPort(c.LocalAddr().String())
	if h.Src != userAddr {
		t.Fatalf("panel saw client %v, want the real user %v", h.Src, userAddr)
	}

	// UDP takes the same way, without PROXY v2.
	uc, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.userPort))))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := uc.Write([]byte("hy2")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "hy2" {
		t.Fatalf("udp echo %q %v", buf[:n], err)
	}

	// The standby path is joined in the background.
	deadline := time.Now().Add(10 * time.Second)
	for {
		s := f.iran.Snapshot().Peers[0].Sessions
		if len(s) == 1 && len(s[0].Paths) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("standby path not joined: %+v", s)
		}
		time.Sleep(50 * time.Millisecond)
	}
	st := f.iran.Snapshot()
	if len(st.Ports) != 1 || st.Ports[0].Rule.TargetPort != f.panelPort {
		t.Fatalf("ports %+v", st.Ports)
	}
	if fs := f.kharej.Snapshot().Forwarder; fs.Streams < 2 {
		t.Fatalf("forwarder stats %+v", fs)
	}
	// Byte counters move while connections are still open.
	if p := st.Ports[0]; p.BytesIn < int64(len("vless handshake bytes")+3) || p.BytesOut < p.BytesIn {
		t.Fatalf("port counters %+v", p)
	}
	if p := st.Peers[0]; p.BytesSent == 0 || p.BytesRecv == 0 {
		t.Fatalf("peer counters %+v", p)
	}
}

func TestReloadAndRevocation(t *testing.T) {
	f := newRelayFixture(t)
	f.waitPeerUp(f.iran, "kharej-01")
	events, unsubscribe := f.iran.Subscribe()
	defer unsubscribe()

	// Move the user-facing port: the old one is released, the new one
	// works, without restarting the node.
	oldPort, newPort := f.userPort, freePort(t)
	next := parse(t, replacePort(f.iranTOML, oldPort, newPort))
	if err := f.iran.Reload(next); err != nil {
		t.Fatal(err)
	}
	if _, err := userRoundTrip(t, oldPort, "x"); err == nil {
		t.Fatal("old port still tunneled after reload")
	}
	c, err := userRoundTrip(t, newPort, "after reload")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitEvent(t, events, EventConfigApplied)

	// Kharej drops iran from its peers: iran's session is revoked at once.
	revoked := parse(t, f.kharejTOML[:strings.Index(f.kharejTOML, "[[peers]]")]+"[api]\nlisten = \"127.0.0.1:1\"\n")
	if err := f.kharej.Reload(revoked); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, events, EventPeerState)
	if _, err := userRoundTrip(t, newPort, "y"); err == nil {
		t.Fatal("traffic still flows to a peer that revoked us")
	}

	if err := f.iran.Reload(parse(t, replaceID(f.iranTOML))); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("node id change: %v", err)
	}
}

func replacePort(s string, from, to uint16) string {
	return strings.ReplaceAll(s, strconv.Itoa(int(from)), strconv.Itoa(int(to)))
}

func replaceID(s string) string { return strings.Replace(s, `"iran-01"`, `"iran-02"`, 1) }

func waitEvent(t *testing.T, ch <-chan Event, typ string) {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-ch:
			if e.Type == typ {
				return
			}
		case <-timeout:
			t.Fatalf("no %s event", typ)
		}
	}
}

func TestStartFailsOnBusyPort(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := l.Addr().(*net.TCPAddr).Port
	id, _ := crypto.GenerateIdentity()
	cfg := parse(t, fmt.Sprintf(`
[node]
id = "solo"
identity_key_file = "unused"
[steering]
tunneled_ports = [%d]
[api]
listen = "127.0.0.1:%d"
`, busy, freePort(t)))
	n, err := New(cfg, id, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err == nil {
		_ = n.Stop()
		t.Fatal("started with a busy port")
	}
	if err := n.Stop(); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("stop after failed start: %v", err)
	}
}

// A user connection whose target refuses must be closed promptly, not left
// hanging until the client gives up.
func TestRefusedTargetClosesUserConnection(t *testing.T) {
	f := newRelayFixture(t)
	f.waitPeerUp(f.iran, "kharej-01")
	closed := freePort(t) // nothing listens here on the kharej side
	next := parse(t, strings.Replace(f.iranTOML, fmt.Sprintf("%d = %d", f.userPort, f.panelPort),
		fmt.Sprintf("%d = %d", f.userPort, closed), 1))
	if err := f.iran.Reload(next); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.userPort))), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("hello"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = c.Read(make([]byte, 16))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("user connection left open after the target refused")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("closed only after %v", time.Since(start))
	}
}
