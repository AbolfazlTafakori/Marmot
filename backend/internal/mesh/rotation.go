package mesh

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"time"
)

// Epoch numbers the rotation epoch that contains now (ADR-0018).
func Epoch(now time.Time, length time.Duration) uint64 {
	if length <= 0 {
		return 0
	}
	return uint64(now.Unix()) / uint64(length/time.Second)
}

// RotatingAddrs derives n addresses of the /64 subnet for an epoch: the
// prefix followed by 64 bits of SHA-256(subnet, seed, epoch, index). The
// same inputs always give the same addresses, so a path's address stays
// valid for the whole epoch. A subnet that is not an IPv6 /64 gives none.
func RotatingAddrs(subnet netip.Prefix, seed string, epoch uint64, n int) []netip.Addr {
	if !subnet.Addr().Is6() || subnet.Bits() != 64 {
		return nil
	}
	prefix := subnet.Masked().Addr().As16()
	out := make([]netip.Addr, 0, n)
	for i := range n {
		h := sha256.New()
		h.Write(prefix[:8])
		h.Write([]byte(seed))
		var b [16]byte
		binary.BigEndian.PutUint64(b[:8], epoch)
		binary.BigEndian.PutUint64(b[8:], uint64(i))
		h.Write(b[:])
		sum := h.Sum(nil)
		a := prefix
		copy(a[8:], sum[:8])
		out = append(out, netip.AddrFrom16(a))
	}
	return out
}
