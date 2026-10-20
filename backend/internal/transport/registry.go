package transport

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrUnknown is returned by Get for a transport that is not compiled in.
var ErrUnknown = errors.New("unknown transport")

// The registry is written only from init() of transport packages and read
// afterwards, which is the one global the contributing rules allow.
var (
	regMu      sync.RWMutex
	registry   = map[string]Transport{}
	duplicates []string
)

// Register adds t to the registry. A duplicate name is a build mistake; it
// is kept out of the registry and reported by Check.
func Register(t Transport) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[t.Name()]; dup {
		duplicates = append(duplicates, t.Name())
		return
	}
	registry[t.Name()] = t
}

// Check reports registration mistakes; main calls it at startup.
func Check() error {
	regMu.RLock()
	defer regMu.RUnlock()
	if len(duplicates) > 0 {
		return fmt.Errorf("transport: duplicate registration of %v", duplicates)
	}
	return nil
}

// Get returns the transport registered under name.
func Get(name string) (Transport, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	t, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknown, name)
	}
	return t, nil
}

// Names lists registered transports, sorted.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
