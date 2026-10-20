//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// reloadSignal delivers SIGHUP, the conventional "reload config" signal.
func reloadSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}
