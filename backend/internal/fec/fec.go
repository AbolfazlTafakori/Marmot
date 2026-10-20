// Package fec groups packets into Reed-Solomon blocks: k source symbols
// and m parity symbols, any k of which rebuild the rest (ARCHITECTURE §8,
// ADR-0014). It knows nothing about paths or packets; session v2 decides
// what a symbol is and where each one travels.
package fec

import (
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/reedsolomon"
)

// Limits on one group.
const (
	MaxData   = 32
	MaxParity = 16
)

// ErrParams means k or m is out of range.
var ErrParams = errors.New("fec: data shards must be 1..32 and parity 1..16")

// codecs caches Reed-Solomon codecs by (k, m); building one costs a
// matrix inversion, and groups closed early use many different k.
var codecs sync.Map // [2]int -> reedsolomon.Encoder

func codec(k, m int) (reedsolomon.Encoder, error) {
	if k < 1 || k > MaxData || m < 1 || m > MaxParity {
		return nil, ErrParams
	}
	key := [2]int{k, m}
	if c, ok := codecs.Load(key); ok {
		return c.(reedsolomon.Encoder), nil
	}
	c, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, fmt.Errorf("fec: %w", err)
	}
	actual, _ := codecs.LoadOrStore(key, c)
	return actual.(reedsolomon.Encoder), nil
}

// Encoder collects the source symbols of the current group. It is not
// safe for concurrent use.
type Encoder struct {
	k, m    int // for the next group
	gk, gm  int // of the open group
	group   uint32
	symbols [][]byte
	maxLen  int
}

// SetParams sets k and m for the groups that start from now on; m = 0
// turns FEC off. The open group keeps the values it started with.
func (e *Encoder) SetParams(k, m int) {
	e.k, e.m = k, m
}

// Params returns k and m for the groups that start from now on.
func (e *Encoder) Params() (k, m int) { return e.k, e.m }

// Enabled reports whether new symbols will be protected.
func (e *Encoder) Enabled() bool {
	if len(e.symbols) > 0 {
		return true
	}
	return e.k > 0 && e.m > 0
}

// Pending is the number of symbols in the open group.
func (e *Encoder) Pending() int { return len(e.symbols) }

// Add puts sym in the open group, starting one if needed, and returns
// where it went. The encoder keeps a copy. When Full reports true the
// caller must Flush before adding more.
func (e *Encoder) Add(sym []byte) (group uint32, index uint8) {
	if len(e.symbols) == 0 {
		e.gk, e.gm = e.k, e.m
		e.maxLen = 0
	}
	index = uint8(len(e.symbols))
	e.symbols = append(e.symbols, append([]byte(nil), sym...))
	e.maxLen = max(e.maxLen, len(sym))
	return e.group, index
}

// Full reports whether the open group has all of its source symbols.
func (e *Encoder) Full() bool { return len(e.symbols) > 0 && len(e.symbols) >= e.gk }

// Flush closes the open group and returns its parity symbols, each
// maxLen bytes long. k is the number of sources actually in the group
// (fewer than configured when it is closed early). With no open group it
// returns ok = false.
func (e *Encoder) Flush() (group uint32, k int, parity [][]byte, ok bool, err error) {
	if len(e.symbols) == 0 {
		return 0, 0, nil, false, nil
	}
	group, k = e.group, len(e.symbols)
	e.group++
	shards := make([][]byte, k+e.gm)
	for i, s := range e.symbols {
		shards[i] = make([]byte, e.maxLen)
		copy(shards[i], s)
	}
	for i := k; i < len(shards); i++ {
		shards[i] = make([]byte, e.maxLen)
	}
	e.symbols = e.symbols[:0]
	c, err := codec(k, e.gm)
	if err != nil {
		return group, k, nil, false, err
	}
	if err := c.Encode(shards); err != nil {
		return group, k, nil, false, fmt.Errorf("fec encode: %w", err)
	}
	return group, k, shards[k:], true, nil
}
