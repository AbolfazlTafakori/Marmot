//go:build linux

package transport

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// FreebindControl lets a socket bind an address not configured on any
// interface, as rotating /64 addresses are (ADR-0018). Use it as the
// Control of a net.Dialer or net.ListenConfig. Failure to set it is not an
// error here: binding such an address then fails with a clear reason.
func FreebindControl(network, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		if strings.HasSuffix(network, "6") {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
		} else {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
		}
	})
}

// FreebindSupported reports whether FreebindControl has any effect.
const FreebindSupported = true
