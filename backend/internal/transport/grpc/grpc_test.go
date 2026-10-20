package grpc

import (
	"bytes"
	"io"
	"testing"
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
