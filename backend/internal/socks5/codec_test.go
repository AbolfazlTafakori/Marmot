package socks5

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

type rw struct {
	*bytes.Reader
	out bytes.Buffer
}

func (x *rw) Write(p []byte) (int, error) { return x.out.Write(p) }

func TestNegotiate(t *testing.T) {
	x := &rw{Reader: bytes.NewReader([]byte{5, 2, 0x02, 0x00})}
	if err := negotiate(x); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x.out.Bytes(), []byte{5, 0}) {
		t.Fatalf("reply %x", x.out.Bytes())
	}
	x = &rw{Reader: bytes.NewReader([]byte{5, 1, 0x02})} // username/password only
	if err := negotiate(x); !errors.Is(err, ErrNoMethod) || !bytes.Equal(x.out.Bytes(), []byte{5, 0xFF}) {
		t.Fatalf("no method: %v %x", err, x.out.Bytes())
	}
	for _, bad := range [][]byte{{4, 1, 0}, {5, 0}} {
		if err := negotiate(&rw{Reader: bytes.NewReader(bad)}); !errors.Is(err, ErrVersion) {
			t.Errorf("%x: %v", bad, err)
		}
	}
}

func TestReadRequest(t *testing.T) {
	cases := []struct {
		in   []byte
		want request
	}{
		{[]byte{5, 1, 0, 1, 192, 0, 2, 1, 0x01, 0xbb}, request{cmd: cmdConnect, dst: Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 443}}},
		{append([]byte{5, 1, 0, 3, 11}, append([]byte("example.com"), 0, 80)...), request{cmd: cmdConnect, dst: Addr{Host: "example.com", Port: 80}}},
		{append(append([]byte{5, 3, 0, 4}, netip.MustParseAddr("2001:db8::1").AsSlice()...), 0, 53), request{cmd: cmdUDPAssociate, dst: Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 53}}},
	}
	for i, c := range cases {
		got, err := readRequest(bytes.NewReader(c.in))
		if err != nil || got != c.want {
			t.Errorf("case %d: %+v %v", i, got, err)
		}
	}
	if _, err := readRequest(bytes.NewReader([]byte{5, 1, 0, 9})); !errors.Is(err, ErrAddrType) {
		t.Fatalf("bad atyp: %v", err)
	}
	if _, err := readRequest(bytes.NewReader([]byte{5, 1, 0, 3, 0, 0, 80})); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("empty domain: %v", err)
	}
	if _, err := readRequest(bytes.NewReader([]byte{5, 1, 0, 3, 3, 'a', 0, 'b', 0, 80})); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("NUL in domain: %v", err)
	}
}

func TestWriteReplyAndAddr(t *testing.T) {
	var b bytes.Buffer
	_ = writeReply(&b, RepSucceeded, Addr{IP: netip.MustParseAddr("127.0.0.1"), Port: 1080})
	if !bytes.Equal(b.Bytes(), []byte{5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38}) {
		t.Fatalf("reply %x", b.Bytes())
	}
	b.Reset()
	_ = writeReply(&b, RepHostUnreachable, Addr{})
	if !bytes.Equal(b.Bytes(), []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("failure reply %x", b.Bytes())
	}
	for _, a := range []struct {
		a    Addr
		want string
	}{
		{Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 1}, "192.0.2.1:1"},
		{Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 2}, "[2001:db8::1]:2"},
		{Addr{Host: "example.com", Port: 3}, "example.com:3"},
	} {
		if a.a.String() != a.want {
			t.Errorf("%+v -> %s", a.a, a.a.String())
		}
	}
}

func TestUDPHeader(t *testing.T) {
	src := Addr{Host: "dns.example", Port: 53}
	pkt := appendUDP(nil, src, []byte("query"))
	dst, data, err := parseUDP(pkt)
	if err != nil || dst != src || string(data) != "query" {
		t.Fatalf("%+v %q %v", dst, data, err)
	}
	if _, _, err := parseUDP([]byte{0, 0, 0, 1, 1}); !errors.Is(err, ErrShortPacket) {
		t.Fatalf("short: %v", err)
	}
	frag := appendUDP(nil, src, nil)
	frag[2] = 1
	if _, _, err := parseUDP(frag); !errors.Is(err, ErrFragmented) {
		t.Fatalf("fragmented: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{5, 1, 0, 1, 192, 0, 2, 1, 0x01, 0xbb})
	f.Add(appendUDP(nil, Addr{Host: "x", Port: 1}, []byte("d")))
	f.Fuzz(func(t *testing.T, b []byte) {
		if req, err := readRequest(bytes.NewReader(b)); err == nil {
			// A parsed address re-encodes to the bytes it came from, except
			// an IPv4-mapped IPv6 address, which is read as plain IPv4.
			enc := appendAddr(nil, req.dst)
			mappedV4 := b[3] == atypIPv6 && req.dst.IP.Is4()
			if !mappedV4 && !bytes.Equal(enc, b[3:3+len(enc)]) {
				t.Fatalf("re-encode mismatch %x vs %x", enc, b[3:])
			}
		}
		_, _, _ = parseUDP(b)
	})
}
