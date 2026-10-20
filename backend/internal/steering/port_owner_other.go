//go:build !linux

package steering

// portOwner is only implemented on Linux, the supported server platform.
func portOwner(uint16) string { return "" }
