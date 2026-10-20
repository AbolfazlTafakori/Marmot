//go:build !unix

package main

import "os"

// reloadSignal never fires where there is no SIGHUP; reload through the
// panel API instead.
func reloadSignal() <-chan os.Signal { return nil }
