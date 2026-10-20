package forwarder

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
)

func TestExitAllowed(t *testing.T) {
	allowed := []string{"1.1.1.1", "198.51.100.7", "2606:4700::1111", "2001:4860::8888"}
	refused := []string{
		"127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", // this host
		"10.0.0.1", "172.16.5.4", "192.168.1.1", "fd00::1", // private
		"169.254.1.1", "fe80::1", // link-local
		"100.64.0.1", "100.127.255.254", // CGNAT
		"0.0.0.0", "0.1.2.3", "::", // unspecified / this network
		"224.0.0.1", "239.1.1.1", "ff02::1", "255.255.255.255", // multicast, broadcast
	}
	for _, s := range allowed {
		if !exitAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range refused {
		if exitAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	if !isLocalAddr(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback not seen as local")
	}
	if exitDestinationAllowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("production rule allows loopback")
	}
}

func exitHeader(proto core.Proto, d frame.Destination) frame.StreamHeader {
	return frame.StreamHeader{Proto: proto, Class: core.ClassTunneled, TargetPort: d.Port, Client: client, Dest: d}
}

func echoTCP(t *testing.T) uint16 {
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

func TestExitRefusals(t *testing.T) {
	port := echoTCP(t)
	noExit := newForwarder(t, Policy{})
	if r := reply(t, serve(t, noExit, exitHeader(core.ProtoTCP, frame.Destination{IP: netip.MustParseAddr("1.1.1.1"), Port: 443}))); r != frame.ReplyDenied {
		t.Fatalf("exit without permission: reply %d", r)
	}
	f := newForwarder(t, Policy{AllowExit: true})
	for _, d := range []frame.Destination{
		{IP: netip.MustParseAddr("127.0.0.1"), Port: port}, // the exit server itself
		{IP: netip.MustParseAddr("10.1.2.3"), Port: 80},    // its internal network
		{Host: "localhost", Port: port},                    // the same, through DNS
	} {
		if r := reply(t, serve(t, f, exitHeader(core.ProtoTCP, d))); r != frame.ReplyDenied {
			t.Errorf("%+v: reply %d, want denied", d, r)
		}
	}
	if r := reply(t, serve(t, f, exitHeader(core.ProtoTCP, frame.Destination{Host: "no-such-host.invalid", Port: 80}))); r != frame.ReplyUnreachable {
		t.Fatalf("unresolvable name: reply %d", r)
	}
}

func TestExitDelivers(t *testing.T) {
	f := newForwarder(t, Policy{AllowExit: true, AllowUDP: true, UDPIdleTimeout: 300 * time.Millisecond,
		AllowDestination: func(netip.Addr) bool { return true }}) // everything here is loopback

	port := echoTCP(t)
	for _, d := range []frame.Destination{
		{IP: netip.MustParseAddr("127.0.0.1"), Port: port},
		{Host: "localhost", Port: port}, // resolved on the exit node
	} {
		c := serve(t, f, exitHeader(core.ProtoTCP, d))
		if r := reply(t, c); r != frame.ReplyOK {
			t.Fatalf("%+v: reply %d", d, r)
		}
		_, _ = c.Write([]byte("hello"))
		got := make([]byte, 5)
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello" {
			t.Fatalf("%+v: echo %q %v", d, got, err)
		}
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
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
	d := frame.Destination{IP: netip.MustParseAddr("127.0.0.1"), Port: uint16(uc.LocalAddr().(*net.UDPAddr).Port)}
	c := serve(t, f, exitHeader(core.ProtoUDP, d))
	if r := reply(t, c); r != frame.ReplyOK {
		t.Fatalf("udp reply %d", r)
	}
	scratch := make([]byte, 2+frame.MaxDatagram)
	buf := make([]byte, frame.MaxDatagram)
	_ = frame.WriteDatagram(c, scratch, []byte("dns?"))
	if n, err := frame.ReadDatagram(c, buf); err != nil || string(buf[:n]) != "dns?" {
		t.Fatalf("udp echo %q %v", buf[:n], err)
	}
}
