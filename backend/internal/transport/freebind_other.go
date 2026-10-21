//go:build !linux

package transport

import "syscall"

// FreebindControl does nothing outside Linux: rotating /64 addresses need
// Linux (ADR-0018).
func FreebindControl(string, string, syscall.RawConn) error { return nil }

// FreebindSupported reports whether FreebindControl has any effect.
const FreebindSupported = false
