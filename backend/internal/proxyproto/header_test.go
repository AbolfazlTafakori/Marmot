package proxyproto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"

	"marmot/internal/core"
)

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		in, want Header
	}{
		{
			in: Header{Command: CmdProxy, Proto: core.ProtoTCP,
				Src: netip.MustParseAddrPort("203.0.113.7:51234"), Dst: netip.MustParseAddrPort("127.0.0.1:443")},
		},
		{
			in: Header{Command: CmdProxy, Proto: core.ProtoUDP,
				Src: netip.MustParseAddrPort("[2001:db8::7]:5"), Dst: netip.MustParseAddrPort("[::1]:8443")},
		},
		{
			// Mixed families become IPv6 with the IPv4 address mapped.
			in: Header{Command: CmdProxy, Proto: core.ProtoTCP,
				Src: netip.MustParseAddrPort("[2001:db8::7]:5"), Dst: netip.MustParseAddrPort("127.0.0.1:443")},
			want: Header{Command: CmdProxy, Proto: core.ProtoTCP,
				Src: netip.MustParseAddrPort("[2001:db8::7]:5"), Dst: netip.MustParseAddrPort("[::ffff:127.0.0.1]:443")},
		},
		{in: Header{Command: CmdLocal}},
	}
	for i, c := range cases {
		b, err := c.in.Append(nil)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		r := bytes.NewReader(append(b, "payload"...))
		got, err := ReadHeader(r)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		want := c.want
		if want == (Header{}) {
			want = c.in
		}
		if got != want {
			t.Fatalf("case %d: got %+v want %+v", i, got, want)
		}
		if r.Len() != len("payload") {
			t.Fatalf("case %d: header reader consumed payload", i)
		}
	}
}

// TestKnownBytes pins the encoding against a header written by hand from
// the specification.
func TestKnownBytes(t *testing.T) {
	h := Header{Command: CmdProxy, Proto: core.ProtoTCP,
		Src: netip.MustParseAddrPort("192.0.2.1:1000"), Dst: netip.MustParseAddrPort("192.0.2.2:443")}
	b, err := h.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "0d0a0d0a000d0a515549540a" + "21" + "11" + "000c" + "c0000201" + "c0000202" + "03e8" + "01bb"
	if hex.EncodeToString(b) != want {
		t.Fatalf("got  %x\nwant %s", b, want)
	}
}

func TestSkipsTLVs(t *testing.T) {
	h := Header{Command: CmdProxy, Proto: core.ProtoTCP,
		Src: netip.MustParseAddrPort("192.0.2.1:1"), Dst: netip.MustParseAddrPort("192.0.2.2:2")}
	b, _ := h.Append(nil)
	tlv := []byte{0x04, 0x00, 0x02, 'h', 'i'} // PP2_TYPE_NOOP
	b[15] += byte(len(tlv))
	b = append(b, tlv...)
	got, err := ReadHeader(bytes.NewReader(b))
	if err != nil || got != h {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestInvalid(t *testing.T) {
	if _, err := (Header{Command: CmdProxy, Proto: core.ProtoTCP}).Append(nil); !errors.Is(err, ErrBadHeader) {
		t.Fatalf("zero addresses: %v", err)
	}
	if _, err := ReadHeader(bytes.NewReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"))); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("v1 header: %v", err)
	}
	bad := func(verCmd, fam byte, n uint16) []byte {
		b := append(Signature[:0:0], Signature[:]...)
		b = append(b, verCmd, fam, byte(n>>8), byte(n))
		return append(b, make([]byte, n)...)
	}
	for i, b := range [][]byte{
		bad(0x11, 0x11, 12), // version 1
		bad(0x22, 0x11, 12), // unknown command
		bad(0x21, 0x13, 12), // unknown protocol
		bad(0x21, 0x31, 12), // AF_UNIX
		bad(0x21, 0x11, 4),  // too short for IPv4
		bad(0x21, 0x21, 12), // too short for IPv6
	} {
		if _, err := ReadHeader(bytes.NewReader(b)); !errors.Is(err, ErrBadHeader) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func FuzzReadHeader(f *testing.F) {
	h := Header{Command: CmdProxy, Proto: core.ProtoTCP,
		Src: netip.MustParseAddrPort("192.0.2.1:1"), Dst: netip.MustParseAddrPort("192.0.2.2:2")}
	b, _ := h.Append(nil)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ReadHeader(bytes.NewReader(b))
		if err != nil || h.Command == CmdLocal {
			return
		}
		if _, err := h.Append(nil); err != nil {
			t.Fatalf("decoded header does not re-encode: %v", err)
		}
	})
}

func BenchmarkAppend(b *testing.B) {
	h := Header{Command: CmdProxy, Proto: core.ProtoTCP,
		Src: netip.MustParseAddrPort("[2001:db8::7]:5"), Dst: netip.MustParseAddrPort("127.0.0.1:443")}
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, _ = h.Append(buf[:0])
	}
}
