package steering

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/session"
)

// echoOpener answers every Open with a pipe whose far end echoes, framing
// UDP datagrams back as they came.
type echoOpener struct {
	mu      sync.Mutex
	headers []frame.StreamHeader
	fail    bool
}

func (o *echoOpener) Open(_ context.Context, _ Rule, h frame.StreamHeader) (session.Stream, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail {
		return nil, errors.New("no peer")
	}
	o.headers = append(o.headers, h)
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		_, _ = io.Copy(far, far)
	}()
	return near, nil
}

func (o *echoOpener) last() frame.StreamHeader {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.headers[len(o.headers)-1]
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func newSteering(t *testing.T, o Opener) *Steering {
	t.Helper()
	s, err := New(Config{Opener: o, UDPIdleTimeout: 400 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func dialEcho(t *testing.T, port uint16, msg string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
		t.Fatalf("echo %q %v", got, err)
	}
	return c
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }

func TestTCPSteeringAndHotUpdate(t *testing.T) {
	o := &echoOpener{}
	s := newSteering(t, o)
	port := freePort(t)
	rule := Rule{Port: port, Class: core.ClassTunneled, Protos: []core.Proto{core.ProtoTCP}, TargetPort: 12052}
	if err := s.Update([]Rule{rule}); err != nil {
		t.Fatal(err)
	}
	c := dialEcho(t, port, "first")
	defer c.Close()
	h := o.last()
	if h.Proto != core.ProtoTCP || h.Class != core.ClassTunneled || h.TargetPort != 12052 || !h.Client.Addr().IsLoopback() {
		t.Fatalf("header %+v", h)
	}

	// Same protocols: the listener and the open connection survive, and
	// new connections use the new rule.
	rule.Class, rule.TargetPort = core.ClassVIP, 443
	if err := s.Update([]Rule{rule}); err != nil {
		t.Fatal(err)
	}
	dialEcho(t, port, "second").Close()
	if h := o.last(); h.Class != core.ClassVIP || h.TargetPort != 443 {
		t.Fatalf("header after update %+v", h)
	}
	if _, err := c.Write([]byte("still")); err != nil {
		t.Fatalf("connection dropped by update: %v", err)
	}
	if ps := s.Ports(); len(ps) != 1 || ps[0].Rule.Class != core.ClassVIP {
		t.Fatalf("ports %+v", ps)
	}

	// Removing the port unbinds it and ends its connections.
	if err := s.Update(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Logf("read after removal: %v", err)
	}
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second); err == nil {
		t.Fatal("port still bound after removal")
	}
}

func TestOpenerFailureClosesConnection(t *testing.T) {
	s := newSteering(t, &echoOpener{fail: true})
	port := freePort(t)
	if err := s.Update([]Rule{{Port: port, Class: core.ClassTunneled, Protos: []core.Proto{core.ProtoTCP}, TargetPort: port}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection without a stream stayed open")
	}
}

func TestPortInUse(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	s := newSteering(t, &echoOpener{})
	err = s.Update([]Rule{{Port: port, Class: core.ClassTunneled, Protos: []core.Proto{core.ProtoTCP}, TargetPort: port}})
	if err == nil {
		t.Fatal("bound a port that is in use")
	}
	if len(s.Ports()) != 0 {
		t.Fatal("failed port is listed")
	}
}

func TestUDPFlows(t *testing.T) {
	o := &echoOpener{}
	s := newSteering(t, o)
	port := freePort(t)
	if err := s.Update([]Rule{{Port: port, Class: core.ClassTunneled, Protos: []core.Proto{core.ProtoUDP}, TargetPort: 2057}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for _, msg := range []string{"hysteria", "again"} {
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("udp echo %q %v", buf[:n], err)
		}
	}
	if h := o.last(); h.Proto != core.ProtoUDP || h.TargetPort != 2057 {
		t.Fatalf("header %+v", h)
	}
	if len(o.headers) != 1 {
		t.Fatalf("one flow expected, got %d streams", len(o.headers))
	}
	if ps := s.Ports(); ps[0].ActiveUDP != 1 {
		t.Fatalf("active flows %d", ps[0].ActiveUDP)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.Ports()[0].ActiveUDP != 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle flow not cleaned up")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{UDPIdleTimeout: time.Second}); err == nil {
		t.Fatal("missing opener accepted")
	}
	if _, err := New(Config{Opener: &echoOpener{}}); err == nil {
		t.Fatal("zero idle timeout accepted")
	}
}
