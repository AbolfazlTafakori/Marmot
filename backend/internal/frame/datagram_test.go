package frame

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestDatagramRoundTrip(t *testing.T) {
	var stream bytes.Buffer
	scratch := make([]byte, 2+MaxDatagram)
	msgs := [][]byte{{}, []byte("hello"), bytes.Repeat([]byte{7}, MaxDatagram)}
	for _, m := range msgs {
		if err := WriteDatagram(&stream, scratch, m); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, MaxDatagram)
	for _, m := range msgs {
		n, err := ReadDatagram(&stream, buf)
		if err != nil || !bytes.Equal(buf[:n], m) {
			t.Fatalf("got %d bytes, %v", n, err)
		}
	}
	if _, err := ReadDatagram(&stream, buf); !errors.Is(err, io.EOF) {
		t.Fatalf("end: %v", err)
	}
	if err := WriteDatagram(&stream, make([]byte, 0, 70000), make([]byte, MaxDatagram+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := ReadDatagram(bytes.NewReader([]byte{0, 5, 1}), make([]byte, 2)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("small buffer: %v", err)
	}
}

func FuzzReadDatagram(f *testing.F) {
	f.Add([]byte{0, 2, 'h', 'i'})
	f.Fuzz(func(t *testing.T, b []byte) {
		buf := make([]byte, MaxDatagram)
		n, err := ReadDatagram(bytes.NewReader(b), buf)
		if err == nil && n != int(b[0])<<8|int(b[1]) {
			t.Fatal("length mismatch")
		}
	})
}
