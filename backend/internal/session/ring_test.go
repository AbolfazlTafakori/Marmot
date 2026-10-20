package session

import (
	"bytes"
	"testing"
)

func TestRingWrapAndRange(t *testing.T) {
	r := newRing(8, 8)
	if n := r.Write([]byte("abcdef")); n != 6 {
		t.Fatalf("write %d", n)
	}
	out := make([]byte, 4)
	if n := r.Read(out); n != 4 || string(out) != "abcd" {
		t.Fatalf("read %d %q", n, out)
	}
	// Wraps around the end of the buffer.
	if n := r.Write([]byte("ghijklmnop")); n != 6 {
		t.Fatalf("write past max: %d", n)
	}
	if r.Free() != 0 || r.Len() != 8 {
		t.Fatalf("len %d free %d", r.Len(), r.Free())
	}
	if got := r.AppendRange([]byte("x"), 1, 5); string(got) != "xfghij" {
		t.Fatalf("range %q", got)
	}
	r.Discard(3)
	rest := make([]byte, 16)
	n := r.Read(rest)
	if string(rest[:n]) != "hijkl" || r.Len() != 0 {
		t.Fatalf("rest %q", rest[:n])
	}
}

func TestRingGrows(t *testing.T) {
	r := newRing(4, 64)
	r.Write([]byte("ab"))
	r.Read(make([]byte, 1)) // head is no longer 0
	big := bytes.Repeat([]byte("z"), 40)
	if n := r.Write(big); n != 40 {
		t.Fatalf("write %d", n)
	}
	got := make([]byte, 64)
	n := r.Read(got)
	if string(got[:n]) != "b"+string(big) {
		t.Fatalf("got %q", got[:n])
	}
	if n := r.Write(make([]byte, 100)); n != 64 {
		t.Fatalf("grow beyond max: %d", n)
	}
}

func BenchmarkRingAppendRange(b *testing.B) {
	r := newRing(1<<20, 1<<20)
	r.Write(make([]byte, 1<<20))
	dst := make([]byte, 0, 16<<10)
	b.ReportAllocs()
	b.SetBytes(16 << 10)
	for i := 0; i < b.N; i++ {
		dst = r.AppendRange(dst[:0], 1000, 16<<10)
	}
}
