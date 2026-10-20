package frame

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"testing"

	"marmot/internal/crypto"
)

// pipePair returns two record conns joined by an in-memory pipe.
func pipePair(t testing.TB) (*Conn, *Conn) {
	t.Helper()
	a, b := mustID(t), mustID(t)
	ca, cb := net.Pipe()
	resp := crypto.NewResponder(b, func(x []byte) (ed25519.PublicKey, bool) { return a.PublicKey(), true })
	type res struct {
		acc crypto.Accepted
		err error
	}
	done := make(chan res, 1)
	go func() {
		acc, err := resp.Respond(cb, func(ed25519.PublicKey, crypto.Hello) crypto.Welcome { return crypto.Welcome{} })
		done <- res{acc, err}
	}()
	keys, _, err := crypto.Initiate(ca, a, b.PublicKey(), crypto.Hello{NodeID: "a"})
	r := <-done
	if err != nil || r.err != nil {
		t.Fatalf("handshake: %v %v", err, r.err)
	}
	return NewConn(ca, keys), NewConn(cb, r.acc.Ciphers)
}

func mustID(t testing.TB) *crypto.Identity {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestConnRoundTrip(t *testing.T) {
	a, b := pipePair(t)
	defer a.Close()
	defer b.Close()

	payload := bytes.Repeat([]byte("x"), MaxDataPayload)
	cases := []struct {
		typ  Type
		body []byte
		pad  int
	}{
		{TypePing, Ping{ID: 1, SentUs: 2}.Append(nil), 0},
		{TypeData, append(AppendOffset(nil, 99), payload...), 0},
		{TypeAck, AppendOffset(nil, 7), 100},
		{TypeClose, CloseBody{Code: CloseShutdown, Reason: "bye"}.Append(nil), 0},
	}
	go func() {
		for _, c := range cases {
			if err := a.WriteRecord(c.typ, c.body, c.pad); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for _, c := range cases {
		typ, body, err := b.ReadRecord()
		if err != nil {
			t.Fatal(err)
		}
		if typ != c.typ || !bytes.Equal(body, c.body) {
			t.Fatalf("got %v len %d, want %v len %d", typ, len(body), c.typ, len(c.body))
		}
	}
}

func TestWriteRecordTooLarge(t *testing.T) {
	a, b := pipePair(t)
	defer a.Close()
	defer b.Close()
	if err := a.WriteRecord(TypeData, make([]byte, MaxBody+1), 0); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if err := a.WriteRecord(TypeData, nil, -1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("negative pad: %v", err)
	}
}

func TestRecordWrongKeyRejected(t *testing.T) {
	x, y := pipePair(t)
	defer x.Close()
	defer y.Close()
	_, q := pipePair(t)
	defer q.Close()

	go x.WriteRecord(TypePing, Ping{}.Append(nil), 0)
	var hdr [2]byte
	if _, err := io.ReadFull(y.rw, hdr[:]); err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, int(hdr[0])<<8|int(hdr[1]))
	if _, err := io.ReadFull(y.rw, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := q.keys.Recv.Decrypt(nil, nil, ct); err == nil {
		t.Fatal("record decrypted under another path's key")
	}
}

func TestBodyCodecs(t *testing.T) {
	off, data, err := ParseData(append(AppendOffset(nil, 5), 'h', 'i'))
	if err != nil || off != 5 || string(data) != "hi" {
		t.Fatalf("data: %d %q %v", off, data, err)
	}
	if v, err := ParseAck(AppendOffset(nil, 9)); err != nil || v != 9 {
		t.Fatalf("ack %d %v", v, err)
	}
	a := Activate{Offset: 1 << 40, Epoch: 3}
	if got, err := ParseActivate(a.Append(nil)); err != nil || got != a {
		t.Fatalf("activate %+v %v", got, err)
	}
	c := CloseBody{Code: 2, Reason: string(bytes.Repeat([]byte("r"), 300))}
	got, err := ParseClose(c.Append(nil))
	if err != nil || got.Code != 2 || len(got.Reason) != 255 {
		t.Fatalf("close %+v %v", got, err)
	}
	for _, bad := range [][]byte{nil, {1}, {0, 0, 5, 'a'}} {
		if _, err := ParseClose(bad); err == nil {
			t.Fatalf("ParseClose(%v) ok", bad)
		}
	}
	if TypeData.String() != "DATA" || Type(0x99).String() != "TYPE(0x99)" {
		t.Fatal("Type.String")
	}
}

func FuzzBodies(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = ParseData(b)
		_, _ = ParseAck(b)
		_, _ = ParsePing(b)
		_, _ = ParseActivate(b)
		if c, err := ParseClose(b); err == nil {
			if !bytes.Equal(c.Append(nil), b) {
				t.Fatal("close re-encode mismatch")
			}
		}
	})
}

func BenchmarkWriteReadRecord(b *testing.B) {
	x, y := pipePair(b)
	defer x.Close()
	defer y.Close()
	body := append(AppendOffset(nil, 0), make([]byte, MaxDataPayload)...)
	go func() {
		for {
			if _, _, err := y.ReadRecord(); err != nil {
				return
			}
		}
	}()
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := x.WriteRecord(TypeData, body, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// TestAppendRecordBatch checks that records built with AppendRecord and
// sent in one WriteRaw read back like separately written ones, and that
// they can be mixed with WriteRecord from the same writer.
func TestAppendRecordBatch(t *testing.T) {
	a, b := pipePair(t)
	defer a.Close()
	defer b.Close()
	go func() {
		var batch []byte
		var err error
		for i := range 3 {
			if batch, err = a.AppendRecord(batch, TypePacket, []byte{byte(i)}, i); err != nil {
				t.Error(err)
				return
			}
		}
		if _, err := a.AppendRecord(batch, TypePacket, make([]byte, MaxBody+1), 0); !errors.Is(err, ErrTooLarge) {
			t.Errorf("oversized record: %v", err)
		}
		if err := a.WriteRaw(batch); err != nil {
			t.Error(err)
		}
		if err := a.WriteRecord(TypePacket, []byte{3}, 0); err != nil {
			t.Error(err)
		}
	}()
	for i := range 4 {
		typ, body, err := b.ReadRecord()
		if err != nil || typ != TypePacket || !bytes.Equal(body, []byte{byte(i)}) {
			t.Fatalf("record %d: %v %x %v", i, typ, body, err)
		}
	}
}
