package fec

import (
	"bytes"
	"math/rand/v2"
	"testing"
	"testing/quick"
	"time"
)

// encodeGroup builds one group of n random sources (lengths vary) and m
// parity symbols.
func encodeGroup(t *testing.T, rng *rand.Rand, n, m int) (sources, parity [][]byte, group uint32) {
	t.Helper()
	var e Encoder
	e.SetParams(n, m)
	for i := range n {
		s := make([]byte, 1+rng.IntN(1100))
		for j := range s {
			s[j] = byte(rng.Uint32())
		}
		sources = append(sources, s)
		if g, idx := e.Add(s); int(idx) != i || g != 0 {
			t.Fatalf("Add returned group %d index %d for source %d", g, idx, i)
		}
	}
	if !e.Full() {
		t.Fatal("group not full after k sources")
	}
	group, k, parity, ok, err := e.Flush()
	if err != nil || !ok || k != n || len(parity) != m {
		t.Fatalf("flush: k=%d parity=%d ok=%v err=%v", k, len(parity), ok, err)
	}
	return sources, parity, group
}

// TestAnyKOfKPlusM is the property of ARCHITECTURE §16: whichever k of
// the k+m symbols arrive, in whatever order, the missing sources are
// rebuilt exactly.
func TestAnyKOfKPlusM(t *testing.T) {
	prop := func(seed uint64, kk, mm uint8) bool {
		rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		k, m := 1+int(kk)%MaxData, 1+int(mm)%MaxParity
		sources, parity, group := encodeGroup(t, rng, k, m)
		order := rng.Perm(k + m)[:k]
		var d Decoder
		var rec []Recovered
		for _, i := range order {
			if i < k {
				rec = append(rec, d.AddSource(group, uint8(i), sources[i])...)
			} else {
				rec = append(rec, d.AddParity(group, uint8(k), uint8(m), uint8(i), parity[i-k])...)
			}
		}
		got := map[int]bool{}
		for _, i := range order {
			got[i] = true
		}
		missing := 0
		for i := range k {
			if !got[i] {
				missing++
			}
		}
		if len(rec) != missing {
			return false
		}
		for _, r := range rec {
			src := sources[r.Index]
			if len(r.Symbol) < len(src) || !bytes.Equal(r.Symbol[:len(src)], src) {
				return false
			}
			if !allZero(r.Symbol[len(src):]) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 300}); err != nil {
		t.Fatal(err)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestTooFewSymbolsRebuildNothing(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	sources, parity, g := encodeGroup(t, rng, 4, 2)
	var d Decoder
	if r := d.AddSource(g, 0, sources[0]); r != nil {
		t.Fatal(r)
	}
	if r := d.AddSource(g, 2, sources[2]); r != nil {
		t.Fatal(r)
	}
	if r := d.AddParity(g, 4, 2, 5, parity[1]); r != nil {
		t.Fatal("rebuilt from 3 of 4")
	}
	r := d.AddParity(g, 4, 2, 4, parity[0])
	if len(r) != 2 || r[0].Index != 1 || r[1].Index != 3 {
		t.Fatalf("recovered %+v", r)
	}
	if r := d.AddSource(g, 1, sources[1]); r != nil {
		t.Fatal("a finished group rebuilt again")
	}
}

func TestNothingMissingNothingRebuilt(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	sources, parity, g := encodeGroup(t, rng, 3, 1)
	var d Decoder
	for i, s := range sources {
		if r := d.AddSource(g, uint8(i), s); r != nil {
			t.Fatal(r)
		}
	}
	if r := d.AddParity(g, 3, 1, 3, parity[0]); r != nil {
		t.Fatal("rebuilt although every source arrived")
	}
}

func TestPartialGroupAndNextGroup(t *testing.T) {
	var e Encoder
	e.SetParams(8, 2)
	e.Add([]byte("a"))
	e.Add([]byte("bcd"))
	g0, k, parity, ok, err := e.Flush()
	if err != nil || !ok || k != 2 || len(parity) != 2 || len(parity[0]) != 3 {
		t.Fatalf("partial flush: k=%d %v %v", k, ok, err)
	}
	if _, _, _, ok, _ := e.Flush(); ok {
		t.Fatal("flush of an empty group")
	}
	if g1, idx := e.Add([]byte("x")); g1 != g0+1 || idx != 0 {
		t.Fatalf("next group %d index %d", g1, idx)
	}
	var d Decoder
	r := d.AddSource(g0, 1, []byte("bcd"))
	r = append(r, d.AddParity(g0, 2, 2, 3, parity[1])...)
	if len(r) != 1 || r[0].Index != 0 || r[0].Symbol[0] != 'a' {
		t.Fatalf("recovered %+v", r)
	}
}

func TestDisabledAndParamsApplyToNextGroup(t *testing.T) {
	var e Encoder
	if e.Enabled() {
		t.Fatal("enabled without params")
	}
	e.SetParams(2, 1)
	e.Add([]byte("a"))
	e.SetParams(4, 0)
	if !e.Enabled() || e.Full() {
		t.Fatal("open group must keep k=2, m=1")
	}
	e.Add([]byte("b"))
	if !e.Full() {
		t.Fatal("group of k=2 not full")
	}
	if _, _, p, ok, err := e.Flush(); !ok || err != nil || len(p) != 1 {
		t.Fatalf("flush: %d %v %v", len(p), ok, err)
	}
	if e.Enabled() {
		t.Fatal("m=0 must disable FEC for the next group")
	}
}

func TestDecoderRejectsInconsistentInput(t *testing.T) {
	var d Decoder
	if d.AddParity(1, 0, 1, 0, []byte{1}) != nil || d.AddParity(1, 2, 1, 1, []byte{1}) != nil ||
		d.AddParity(1, 2, 1, 3, []byte{1}) != nil || d.AddParity(1, MaxData+1, 1, MaxData+1, []byte{1}) != nil {
		t.Fatal("bad parity accepted")
	}
	// A source longer than the parity symbols spoils the group.
	d.AddParity(2, 2, 1, 2, []byte{1, 2})
	d.AddSource(2, 0, []byte{1, 2, 3})
	if r := d.AddSource(2, 1, []byte{1}); r != nil {
		t.Fatal("rebuilt from an inconsistent group")
	}
	// Parity with a different k for the same group spoils it too.
	d.AddSource(3, 0, []byte{1})
	d.AddParity(3, 2, 2, 2, []byte{9})
	if r := d.AddParity(3, 3, 1, 3, []byte{9}); r != nil {
		t.Fatal("mixed k accepted")
	}
}

func TestDecoderExpiresAndBoundsGroups(t *testing.T) {
	now := time.Unix(0, 0)
	d := Decoder{Now: func() time.Time { return now }}
	d.AddSource(1, 0, []byte{1})
	now = now.Add(2 * time.Second)
	d.AddSource(2, 0, []byte{1})
	if _, ok := d.groups[1]; ok {
		t.Fatal("old group kept")
	}
	for i := range maxGroups + 10 {
		d.AddSource(uint32(100+i), 0, []byte{1})
	}
	if len(d.groups) > maxGroups {
		t.Fatalf("%d groups held", len(d.groups))
	}
}

func BenchmarkEncodeGroup(b *testing.B) {
	sym := bytes.Repeat([]byte{1}, 1100)
	var e Encoder
	e.SetParams(4, 2)
	b.SetBytes(4 * 1100)
	b.ReportAllocs()
	for b.Loop() {
		for range 4 {
			e.Add(sym)
		}
		_, _, _, _, _ = e.Flush()
	}
}
