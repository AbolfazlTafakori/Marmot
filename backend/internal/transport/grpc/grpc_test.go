package grpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"marmot/internal/transport"
)

func msg(flag byte, payload string) []byte {
	b := []byte{flag, 0, 0, 0, byte(len(payload))}
	return append(b, payload...)
}

func TestConnReadsMessagesBackToBack(t *testing.T) {
	var wire []byte
	wire = append(wire, msg(0, "hello ")...)
	wire = append(wire, msg(0, "")...) // empty messages are legal
	wire = append(wire, msg(0, "world")...)
	c := &conn{r: bytes.NewReader(wire)}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "hello world" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestConnRejects(t *testing.T) {
	cases := map[string][]byte{
		"compressed": msg(1, "x"),
		"too large":  {0, 0xff, 0xff, 0xff, 0xff},
		"truncated":  msg(0, "abc")[:6],
	}
	for name, wire := range cases {
		c := &conn{r: bytes.NewReader(wire)}
		if _, err := io.ReadAll(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConnWriteFrames(t *testing.T) {
	var buf bytes.Buffer
	c := &conn{w: &buf, flush: func() error { return nil }, closeFn: func() error { return nil }}
	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), msg(0, "abc")) {
		t.Fatalf("wire %x", buf.Bytes())
	}
	_ = c.Close()
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("write after close accepted")
	}
}

func FuzzConnRead(f *testing.F) {
	f.Add(msg(0, "seed"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		c := &conn{r: bytes.NewReader(wire)}
		buf := make([]byte, 7)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	})
}

// A client that gives up while the session handshake runs ends the HTTP
// handler; the handshake's deadline cleanup must then leave the response
// writer alone (it raced with net/http and could panic).
func TestDeadlineAfterClientLeft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := Transport{}.Listen(ctx, transport.ListenConfig{Addr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan transport.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	c, err := Transport{}.Dial(ctx, transport.Endpoint{Addr: netip.MustParseAddrPort(l.Addr().String())}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	d := s.(interface{ SetDeadline(time.Time) error })
	if err := d.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("deadline while the call is live: %v", err)
	}
	_ = c.Close()
	for start := time.Now(); d.SetDeadline(time.Time{}) == nil; {
		if time.Since(start) > 5*time.Second {
			t.Fatal("handler never ended after the client left")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := d.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("deadline after the handler ended: %v", err)
	}
}
