//go:build linux

package steering

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"marmot/internal/core"
)

func TestPortOwnerNamesProcess(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	owner := portOwner(port)
	if !strings.HasSuffix(owner, fmt.Sprintf("(pid %d)", os.Getpid())) {
		t.Fatalf("owner %q, want this test process", owner)
	}

	// And the steering error carries it.
	s := newSteering(t, &echoOpener{})
	err = s.Update([]Rule{{Port: port, Class: core.ClassTunneled, Protos: []core.Proto{core.ProtoTCP}, TargetPort: port}})
	if err == nil || !strings.Contains(err.Error(), "already used by") {
		t.Fatalf("err = %v", err)
	}
}

func TestPortOwnerUnusedPort(t *testing.T) {
	l, _ := net.Listen("tcp", ":0")
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	if owner := portOwner(port); owner != "" {
		t.Fatalf("free port has owner %q", owner)
	}
}

func TestPortOwnerUDP(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if owner := portOwner(uint16(c.LocalAddr().(*net.UDPAddr).Port)); owner == "" {
		t.Fatal("udp socket owner not found")
	}
}
