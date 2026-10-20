package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that decodes from strings such as "30s".
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", b)
	}
	*d = Duration(v)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// ByteSize is a byte count that decodes from strings such as "25MiB" or "4KB".
type ByteSize int64

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}, {"B", 1},
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *ByteSize) UnmarshalText(b []byte) error {
	str := strings.TrimSpace(string(b))
	mult := int64(1)
	for _, u := range byteUnits {
		if strings.HasSuffix(str, u.suffix) {
			str, mult = strings.TrimSpace(strings.TrimSuffix(str, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(str, 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid byte size %q", b)
	}
	if n > (1<<62)/mult {
		return fmt.Errorf("byte size %q overflows", b)
	}
	*s = ByteSize(n * mult)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (s ByteSize) MarshalText() ([]byte, error) { return []byte(strconv.FormatInt(int64(s), 10)), nil }

// PortRange is an inclusive range "lo-hi". The zero value means unset.
type PortRange struct {
	Lo, Hi uint16
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (r *PortRange) UnmarshalText(b []byte) error {
	lo, hi, ok := strings.Cut(string(b), "-")
	if !ok {
		return fmt.Errorf("invalid port range %q, want lo-hi", b)
	}
	l, err1 := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	h, err2 := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err1 != nil || err2 != nil || l == 0 || l > h {
		return fmt.Errorf("invalid port range %q", b)
	}
	r.Lo, r.Hi = uint16(l), uint16(h)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (r PortRange) MarshalText() ([]byte, error) {
	if r.IsZero() {
		return []byte(""), nil
	}
	return []byte(fmt.Sprintf("%d-%d", r.Lo, r.Hi)), nil
}

// IsZero reports whether the range is unset.
func (r PortRange) IsZero() bool { return r.Lo == 0 && r.Hi == 0 }

// Contains reports whether p is inside the range.
func (r PortRange) Contains(p uint16) bool { return !r.IsZero() && p >= r.Lo && p <= r.Hi }
