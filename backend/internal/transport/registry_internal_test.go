package transport

import (
	"context"
	"net/netip"
	"testing"
)

type fakeTransport struct{ name string }

func (f fakeTransport) Name() string { return f.name }
func (fakeTransport) Kind() Kind     { return Stream }
func (fakeTransport) Dial(context.Context, Endpoint, netip.Addr) (Conn, error) {
	return nil, nil
}
func (fakeTransport) Listen(context.Context, ListenConfig) (Listener, error) { return nil, nil }

func TestDuplicateRegistrationReported(t *testing.T) {
	regMu.Lock()
	savedReg, savedDup := registry, duplicates
	registry, duplicates = map[string]Transport{}, nil
	regMu.Unlock()
	t.Cleanup(func() {
		regMu.Lock()
		registry, duplicates = savedReg, savedDup
		regMu.Unlock()
	})

	Register(fakeTransport{"x"})
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	Register(fakeTransport{"x"})
	if err := Check(); err == nil {
		t.Fatal("duplicate not reported")
	}
	if len(Names()) != 1 {
		t.Fatalf("names %v", Names())
	}
}

func TestOptions(t *testing.T) {
	opts := map[string]any{"s": "v", "b": true, "n": 3}
	if v, err := StringOption(opts, "s", ""); err != nil || v != "v" {
		t.Fatal(v, err)
	}
	if v, err := StringOption(opts, "missing", "d"); err != nil || v != "d" {
		t.Fatal(v, err)
	}
	if _, err := StringOption(opts, "n", ""); err == nil {
		t.Fatal("number accepted as string")
	}
	if v, err := BoolOption(opts, "b", false); err != nil || !v {
		t.Fatal(v, err)
	}
	if v, err := BoolOption(opts, "missing", true); err != nil || !v {
		t.Fatal(v, err)
	}
	if _, err := BoolOption(opts, "s", false); err == nil {
		t.Fatal("string accepted as bool")
	}
}
