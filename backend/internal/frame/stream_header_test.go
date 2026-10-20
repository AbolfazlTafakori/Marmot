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
	h.TargetPort, h.Dest = 443, Destination{Host: "example.com", Port: 443}
	b, _ = h.MarshalBinary()
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

func TestExitHeaderRoundTrip(t *testing.T) {
	base := StreamHeader{Proto: core.ProtoTCP, Class: core.ClassTunneled, Client: netip.MustParseAddrPort("127.0.0.1:40000")}
	for _, d := range []Destination{
		{IP: netip.MustParseAddr("198.51.100.7"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::7"), Port: 80},
		{Host: "www.example.com", Port: 8443},
	} {
		h := base
		h.TargetPort, h.Dest = d.Port, d
		b, err := h.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if b[0] != StreamHeaderVersionExit {
			t.Fatalf("version %d", b[0])
		}
		got, err := ReadStreamHeader(bytes.NewReader(b))
		if err != nil || got.Dest != d || got.TargetPort != d.Port {
			t.Fatalf("%+v: got %+v %v", d, got, err)
		}
	}
}

// A header without a destination must stay exactly version 1, so relay
// streams are unchanged on the wire.
func TestRelayHeaderStaysVersion1(t *testing.T) {
	h := StreamHeader{Proto: core.ProtoTCP, Class: core.ClassTunneled, TargetPort: 443,
		Client: netip.MustParseAddrPort("203.0.113.9:51000")}
	b, _ := h.MarshalBinary()
	want := []byte{1, 1, 1, 0x01, 0xbb, 4, 203, 0, 113, 9, 0xc7, 0x38, 0}
	if !bytes.Equal(b, want) {
		t.Fatalf("got %x want %x", b, want)
	}
}

func TestExitHeaderInvalid(t *testing.T) {
	base := StreamHeader{Proto: core.ProtoTCP, Class: core.ClassTunneled, TargetPort: 443,
		Client: netip.MustParseAddrPort("127.0.0.1:1")}
	bad := []Destination{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 80},             // port differs from target_port
		{Host: "", Port: 443, IP: netip.Addr{}},                      // nothing but a port
		{IP: netip.MustParseAddr("192.0.2.1"), Host: "x", Port: 443}, // both
		{Host: "bad host", Port: 443},                                // space
		{Host: "a\x00b", Port: 443},                                  // control character
		{Host: string(bytes.Repeat([]byte("a"), 256)), Port: 443},    // too long
	}
	for i, d := range bad {
		h := base
		h.Dest = d
		if _, err := h.MarshalBinary(); err == nil {
			t.Errorf("case %d accepted: %+v", i, d)
		}
	}
	good := base
	good.Dest = Destination{Host: "example.com", Port: 443}
	b, _ := good.MarshalBinary()
	for i, mutate := range []func([]byte){
		func(b []byte) { b[len(b)-15] = 9 }, // unknown destination type
		func(b []byte) { b[len(b)-1]++ },    // dst_port no longer matches
		func(b []byte) { b[len(b)-13] = 0 }, // control character in the name
	} {
		x := append([]byte(nil), b...)
		mutate(x)
		if _, err := ReadStreamHeader(bytes.NewReader(x)); err == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
	if _, err := ReadStreamHeader(bytes.NewReader(append([]byte{3}, b[1:]...))); err == nil {
		t.Fatal("version 3 accepted")
	}
}

func TestPathHeaderRoundTrip(t *testing.T) {
	for _, route := range [][]core.NodeID{nil, {"kharej-1"}, {"relay-2", "kharej-1"}} {
		h := StreamHeader{Path: true, Route: route}
		b, err := h.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if b[0] != StreamHeaderVersionPath || int(b[1]) != len(route) {
			t.Fatalf("encoding %x", b)
		}
		got, err := ReadStreamHeader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, h) {
			t.Fatalf("got %+v want %+v", got, h)
		}
	}
}

func TestPathHeaderInvalid(t *testing.T) {
	bad := []StreamHeader{
		{Path: true, TargetPort: 443},
		{Path: true, Proto: core.ProtoTCP},
		{Path: true, Client: netip.MustParseAddrPort("1.2.3.4:5")},
		{Path: true, Route: []core.NodeID{"a", "b", "c", "d", "e"}},
		{Path: true, Route: []core.NodeID{""}},
	}
	for i, h := range bad {
		if _, err := h.MarshalBinary(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, b := range [][]byte{{3, 5}, {3, 1, 0}, {3, 1, 3, 'a'}, {3}} {
		if _, err := ReadStreamHeader(bytes.NewReader(b)); err == nil {
			t.Errorf("ReadStreamHeader(%v) accepted", b)
		}
	}
}
