package core

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestGetPutBuf(t *testing.T) {
	tests := []struct {
		size    int
		wantCap int
	}{
		{1, SmallBufSize},
		{SmallBufSize, SmallBufSize},
		{SmallBufSize + 1, LargeBufSize},
		{LargeBufSize, LargeBufSize},
		{LargeBufSize + 1, LargeBufSize + 1},
	}
	for _, tt := range tests {
		bp := GetBuf(tt.size)
		if len(*bp) != tt.size {
			t.Fatalf("GetBuf(%d): len %d", tt.size, len(*bp))
		}
		if cap(*bp) != tt.wantCap {
			t.Fatalf("GetBuf(%d): cap %d, want %d", tt.size, cap(*bp), tt.wantCap)
		}
		PutBuf(bp)
	}
	PutBuf(nil)
}

func TestParseNodeID(t *testing.T) {
	valid := []string{"a", "iran-gateway-01", "0x", "k123"}
	for _, s := range valid {
		if _, err := ParseNodeID(s); err != nil {
			t.Errorf("ParseNodeID(%q) = %v", s, err)
		}
	}
	invalid := []string{"", "-a", "A", "a_b", "a b", string(make([]byte, MaxNodeIDLen+1))}
	for _, s := range invalid {
		if _, err := ParseNodeID(s); !errors.Is(err, ErrInvalidNodeID) {
			t.Errorf("ParseNodeID(%q) err = %v, want ErrInvalidNodeID", s, err)
		}
	}
}

func TestClassAndProto(t *testing.T) {
	if !ClassTunneled.Valid() || !ClassVIP.Valid() || Class(9).Valid() {
		t.Fatal("Class.Valid")
	}
	if ClassVIP.String() != "vip" || Class(9).String() != "class(9)" {
		t.Fatal("Class.String")
	}
	for _, s := range []string{"tcp", "udp"} {
		p, err := ParseProto(s)
		if err != nil || p.String() != s {
			t.Fatalf("ParseProto(%q) = %v, %v", s, p, err)
		}
	}
	if _, err := ParseProto("sctp"); err == nil {
		t.Fatal("ParseProto(sctp) should fail")
	}
}

func BenchmarkGetPutBufLarge(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		PutBuf(GetBuf(LargeBufSize))
	}
}

func TestPipe(t *testing.T) {
	// client <-> [a  Pipe  b] <-> server
	client, a := net.Pipe()
	b, server := net.Pipe()
	done := make(chan [2]int64, 1)
	go func() {
		x, y := Pipe(a, b)
		done <- [2]int64{x, y}
	}()
	go func() {
		buf := make([]byte, 5)
		_, _ = io.ReadFull(server, buf)
		_, _ = server.Write([]byte("pong!!"))
		_ = server.Close()
	}()
	if _, err := client.Write([]byte("ping!")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || string(got) != "pong!!" {
		t.Fatalf("got %q %v", got, err)
	}
	if n := <-done; n != [2]int64{5, 6} {
		t.Fatalf("counts %v", n)
	}
}
