package frame

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestFramesRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 300)
	ranges := []AckRange{{Lo: 90, Hi: 100}, {Lo: 50, Hi: 60}, {Lo: 0, Hi: 0}}
	var b []byte
	b = AppendPacketHeader(b, 1<<40)
	b = AppendPing(b)
	b = AppendAck(b, 1234, ranges)
	b = AppendStream(b, 7, 1<<33, true, data)
	b = AppendStream(b, math.MaxUint32, 0, false, nil)
	b = AppendReset(b, 9, 3, 1<<30)
	b = AppendStop(b, 11)
	b = AppendMaxStreamData(b, 13, 1<<21)
	b = AppendMaxData(b, 1<<24)
	b = AppendDatagram(b, 15, []byte("udp"))

	pn, rest, err := ParsePacket(b)
	if err != nil || pn != 1<<40 {
		t.Fatalf("packet header: %d %v", pn, err)
	}
	want := []Frame{
		{Type: FramePing},
		{Type: FrameAck, Ranges: ranges, DelayUs: 1234},
		{Type: FrameStream, StreamID: 7, Offset: 1 << 33, Fin: true, Data: data},
		{Type: FrameStream, StreamID: math.MaxUint32, Data: []byte{}},
		{Type: FrameReset, StreamID: 9, Code: 3, Final: 1 << 30},
		{Type: FrameStop, StreamID: 11},
		{Type: FrameMaxStreamData, StreamID: 13, Max: 1 << 21},
		{Type: FrameMaxData, Max: 1 << 24},
		{Type: FrameDatagram, StreamID: 15, Data: []byte("udp")},
	}
	var f Frame
	for i, w := range want {
		rest, err = ParseFrame(rest, &f)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		got := f
		if got.Type != FrameAck {
			got.Ranges = nil
		}
		if !reflect.DeepEqual(got, w) {
			t.Fatalf("frame %d:\n got %+v\nwant %+v", i, got, w)
		}
	}
	if len(rest) != 0 {
		t.Fatalf("%d bytes left", len(rest))
	}
}

func TestStreamOverhead(t *testing.T) {
	for _, c := range []struct {
		id  uint32
		off uint64
		n   int
	}{{1, 0, 0}, {1 << 20, 1 << 40, 16000}, {math.MaxUint32, math.MaxUint64 - 1, 1}} {
		data := make([]byte, c.n)
		if got := len(AppendStream(nil, c.id, c.off, false, data)) - c.n; got != StreamOverhead(c.id, c.off, c.n) {
			t.Fatalf("%+v: overhead %d, StreamOverhead %d", c, got, StreamOverhead(c.id, c.off, c.n))
		}
	}
}

func TestAckRangesCapped(t *testing.T) {
	var ranges []AckRange
	for i := 100; i > 0; i-- {
		ranges = append(ranges, AckRange{Lo: uint64(i * 3), Hi: uint64(i*3 + 1)})
	}
	var f Frame
	if _, err := ParseFrame(AppendAck(nil, 0, ranges), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Ranges) != MaxAckRanges || f.Ranges[0] != ranges[0] {
		t.Fatalf("got %d ranges, first %+v", len(f.Ranges), f.Ranges[0])
	}
}

func TestParseFrameRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":              {},
		"unknown":            {0x7f},
		"bad fin":            {byte(FrameStream), 1, 0, 2, 0},
		"short data":         {byte(FrameStream), 1, 0, 0, 5, 1, 2},
		"stream id too big":  append([]byte{byte(FrameStop)}, 0x80, 0x80, 0x80, 0x80, 0x10),
		"truncated varint":   {byte(FrameMaxData), 0x80},
		"ack first>largest":  {byte(FrameAck), 3, 0, 0, 4},
		"ack below zero":     {byte(FrameAck), 3, 0, 1, 0, 2, 0},
		"ack too many":       {byte(FrameAck), 100, 0, MaxAckRanges, 0},
		"offset overflow":    append([]byte{byte(FrameStream), 1}, append(maxUvarint(), 0, 1, 9)...),
		"ack range overflow": {byte(FrameAck), 10, 0, 1, 2, 0, 9},
	}
	for name, b := range cases {
		var f Frame
		if _, err := ParseFrame(b, &f); err == nil {
			t.Errorf("%s: accepted %x", name, b)
		}
	}
}

func maxUvarint() []byte { return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01} }

func TestFECHeaders(t *testing.T) {
	src := FECSource{PN: 5, Group: 6, Index: 2}
	h, frames, err := ParseFECSource(append(src.Append(nil), 1, 2))
	if err != nil || h != src || !bytes.Equal(frames, []byte{1, 2}) {
		t.Fatalf("source: %+v %x %v", h, frames, err)
	}
	rep := FECRepair{PN: 9, Group: 6, K: 4, M: 2, Index: 5}
	r, parity, err := ParseFECRepair(append(rep.Append(nil), 0xaa))
	if err != nil || r != rep || !bytes.Equal(parity, []byte{0xaa}) {
		t.Fatalf("repair: %+v %x %v", r, parity, err)
	}
	for _, bad := range []FECRepair{{K: 0, M: 1}, {K: 2, M: 0}, {K: 2, M: 1, Index: 1}, {K: 2, M: 1, Index: 3}} {
		if _, _, err := ParseFECRepair(append(bad.Append(nil), 0)); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	sym := AppendFECSymbol(nil, 1<<60, 77, []byte("frames"))
	sym = append(sym, 0, 0, 0) // padding
	id, pn, fr, err := ParseFECSymbol(sym)
	if err != nil || id != 1<<60 || pn != 77 || string(fr) != "frames" {
		t.Fatalf("symbol: %x %d %q %v", id, pn, fr, err)
	}
	if _, _, _, err := ParseFECSymbol(sym[:FECSymbolHeader+2]); !errors.Is(err, ErrShortBody) {
		t.Fatalf("truncated symbol: %v", err)
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(AppendAck(nil, 5, []AckRange{{Lo: 9, Hi: 10}, {Lo: 1, Hi: 3}}))
	f.Add(AppendStream(nil, 3, 99, true, []byte("abc")))
	f.Add(AppendMaxStreamData(nil, 2, 1<<20))
	f.Fuzz(func(t *testing.T, b []byte) {
		var fr Frame
		for len(b) > 0 {
			rest, err := ParseFrame(b, &fr)
			if err != nil {
				return
			}
			if len(rest) >= len(b) {
				t.Fatal("no progress")
			}
			if fr.Type == FrameAck {
				for i, r := range fr.Ranges {
					if r.Lo > r.Hi || (i > 0 && r.Hi+2 > fr.Ranges[i-1].Lo) {
						t.Fatalf("bad ranges %+v", fr.Ranges)
					}
				}
			}
			b = rest
		}
	})
}

func FuzzParseFEC(f *testing.F) {
	f.Add(FECRepair{PN: 1, Group: 2, K: 3, M: 1, Index: 3}.Append(nil))
	f.Add(AppendFECSymbol(nil, 1, 2, []byte("x")))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = ParseFECSource(b)
		_, _, _ = ParseFECRepair(b)
		if _, _, fr, err := ParseFECSymbol(b); err == nil && len(fr) > len(b) {
			t.Fatal("frames beyond symbol")
		}
	})
}
