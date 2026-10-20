package config

import (
	"reflect"
	"testing"
)

func TestMarshalRoundTrip(t *testing.T) {
	first, err := Parse([]byte(validTOML()))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Marshal(first.Config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse(out)
	if err != nil {
		t.Fatalf("marshalled config does not parse: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(first.Config, second.Config) {
		t.Fatalf("round trip changed the config:\n%+v\n%+v\n%s", first.Config, second.Config, out)
	}
}
