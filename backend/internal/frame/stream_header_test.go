package frame

import (
	"bytes"
	"net/netip"
	"reflect"
	"testing"

	"marmot/internal/core"
)

func TestStreamHeaderRoundTrip(t *testing.T) {
	cases := []StreamHeader{
		{Proto: core.ProtoTCP, Class: core.ClassTunneled, TargetPort: 443, Client: netip.MustParseAddrPort("203.0.113.9:51000")},
		{Proto: core.ProtoUDP, Class: core.ClassVIP, TargetPort: 62050, Client: netip.MustParseAddrPort("[2001:db8::1]:7"),
			Route: []core.NodeID{"relay-1", "kharej-2"}},
		{Proto: core.ProtoTCP, Class: core.ClassTunneled, TargetPort: 1, Client: netip.MustParseAddrPort("[::ffff:192.0.2.1]:9")},
	}
	for _, h := range cases {
		b, err := h.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadStreamHeader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		want := h
		want.Client = netip.AddrPortFrom(h.Client.Addr().Unmap(), h.Client.Port())
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
}

func TestStreamHeaderInvalid(t *testing.T) {
	bad := []StreamHeader{
		{Proto: 9, Class: core.ClassTunneled, TargetPort: 1, Client: netip.MustParseAddrPort("1.2.3.4:5")},
		{Proto: core.ProtoTCP, Class: 0, TargetPort: 1, Client: netip.MustParseAddrPort("1.2.3.4:5")},
		{Proto: core.ProtoTCP, Class: core.ClassVIP, TargetPort: 0, Client: netip.MustParseAddrPort("1.2.3.4:5")},
		{Proto: core.ProtoTCP, Class: core.ClassVIP, TargetPort: 1},
		{Proto: core.ProtoTCP, Class: core.ClassVIP, TargetPort: 1, Client: netip.MustParseAddrPort("1.2.3.4:5"),
			Route: []core.NodeID{"a", "b", "c", "d", "e"}},
	}
	for i, h := range bad {
		if _, err := h.MarshalBinary(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, b := range [][]byte{{2, 1, 1, 0, 1, 4}, {1, 1, 1, 0, 1, 5}, {1, 1, 1, 0, 0, 4}} {
		if _, err := ReadStreamHeader(bytes.NewReader(b)); err == nil {
			t.Errorf("ReadStreamHeader(%v) accepted", b)
		}
	}
}

func FuzzReadStreamHeader(f *testing.F) {
	h := StreamHeader{Proto: core.ProtoTCP, Class: core.ClassTunneled, TargetPort: 443,
		Client: netip.MustParseAddrPort("1.2.3.4:5"), Route: []core.NodeID{"x"}}
	b, _ := h.MarshalBinary()
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ReadStreamHeader(bytes.NewReader(b))
		if err != nil {
			return
		}
		enc, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("decoded header does not re-encode: %v", err)
		}
		if !bytes.Equal(enc, b[:len(enc)]) {
			t.Fatal("re-encode mismatch")
		}
	})
}
