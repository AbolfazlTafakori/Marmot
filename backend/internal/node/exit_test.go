package node

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"marmot/internal/config"
	"marmot/internal/crypto"
)

// startExitPair runs the exit-mode topology of ARCHITECTURE §3.2:
//
//	client ──SOCKS5──► iran (socks5 inbound) ══ tls ══► kharej (exit) ──► destination
//
// and returns the SOCKS5 address on iran.
func startExitPair(t *testing.T, kharejRole string, allowAll bool) string {
	t.Helper()
	iranID, _ := crypto.GenerateIdentity()
	kharejID, _ := crypto.GenerateIdentity()
	inter, socksPort := freePort(t), freePort(t)
	kharejTOML := fmt.Sprintf(`
[node]
id = "kharej-01"
role = %q
identity_key_file = "unused"
[[transport_listen]]
transport = "tls"
port = %d
[[peers]]
id = "iran-01"
public_key = %q
[api]
listen = "127.0.0.1:%d"
`, kharejRole, inter, config.FormatPublicKey(iranID.PublicKey()), freePort(t))
	iranTOML := fmt.Sprintf(`
[node]
id = "iran-01"
identity_key_file = "unused"
[socks5]
enabled = true
listen = "127.0.0.1:%d"
[[peers]]
id = "kharej-01"
public_key = %q
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [%d]
[api]
listen = "127.0.0.1:%d"
`, socksPort, config.FormatPublicKey(kharejID.PublicKey()), inter, freePort(t))

	opts := Options{}
	if allowAll {
		opts.exitDestinations = func(netip.Addr) bool { return true } // everything here is loopback
	}
	kharej, err := New(parse(t, kharejTOML), kharejID, opts)
	if err != nil {
		t.Fatal(err)
	}
	iran, err := New(parse(t, iranTOML), iranID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{kharej, iran} {
		if err := n.Start(); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = iran.Stop()
		_ = kharej.Stop()
	})
	f := &relayFixture{t: t}
	f.waitPeerUp(iran, "kharej-01")
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(socksPort)))
}

// socksRequest sends a SOCKS5 request for host:port and returns the
// connection and the reply code.
func socksRequest(t *testing.T, socks string, cmd byte, host string, port uint16) (net.Conn, byte, uint16) {
	t.Helper()
	c, err := net.Dial("tcp", socks)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req := []byte{5, 1, 0, 5, cmd, 0}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		v := ip.As4()
		req = append(append(req, 1), v[:]...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	r := make([]byte, 2+10) // method reply, then an IPv4 bound address reply
	if _, err := io.ReadFull(c, r); err != nil {
		t.Fatalf("reply: %v", err)
	}
	return c, r[3], binary.BigEndian.Uint16(r[10:])
}

func TestExitModeEndToEnd(t *testing.T) {
	socks := startExitPair(t, "exit", true)
	echo := echoServer(t)

	for _, host := range []string{"127.0.0.1", "localhost"} {
		c, rep, _ := socksRequest(t, socks, 1, host, echo)
		if rep != 0 {
			t.Fatalf("%s: reply %d", host, rep)
		}
		_, _ = c.Write([]byte("through the exit"))
		got := make([]byte, 16)
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "through the exit" {
			t.Fatalf("%s: echo %q %v", host, got, err)
		}
		c.Close()
	}

	// UDP: associate, send one datagram to a UDP echo, get it back.
	uecho := udpEchoServer(t)
	ctl, rep, udpPort := socksRequest(t, socks, 3, "0.0.0.0", 0)
	defer ctl.Close()
	if rep != 0 {
		t.Fatalf("udp associate reply %d", rep)
	}
	uc, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(udpPort))))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(10 * time.Second))
	pkt := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(uecho >> 8), byte(uecho)}
	if _, err := uc.Write(append(pkt, "ping"...)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := uc.Read(buf)
	if err != nil || string(buf[10:n]) != "ping" {
		t.Fatalf("udp echo %q %v", buf[:n], err)
	}
}

func TestExitModeRefusals(t *testing.T) {
	echo := echoServer(t)
	cases := []struct {
		name string
		role string
		host string
		want byte
	}{
		// The real rule: an exit never connects to its own host.
		{"own host", "exit", "127.0.0.1", 2},
		{"own host by name", "exit", "localhost", 2},
		// A node whose role is relay does not exit at all.
		{"relay role", "relay", "1.1.1.1", 2},
		// Names are resolved on the exit; an unknown one is unreachable.
		{"unknown name", "exit", "no-such-host.invalid", 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			socks := startExitPair(t, c.role, false)
			conn, rep, _ := socksRequest(t, socks, 1, c.host, echo)
			conn.Close()
			if rep != c.want {
				t.Fatalf("reply %d, want %d", rep, c.want)
			}
		})
	}
}

func echoServer(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func udpEchoServer(t *testing.T) uint16 {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uc.Close() })
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
	return uint16(uc.LocalAddr().(*net.UDPAddr).Port)
}
