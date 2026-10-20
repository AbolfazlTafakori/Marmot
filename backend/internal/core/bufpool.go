package core

import "sync"

// Buffer size classes. Hot paths take buffers from these pools so that the
// per-packet path does not allocate.
const (
	SmallBufSize = 2 << 10  // 2 KiB: headers, control records, UDP datagrams
	LargeBufSize = 32 << 10 // 32 KiB: bulk copy and record payloads
)

var (
	smallPool = sync.Pool{New: func() any { b := make([]byte, SmallBufSize); return &b }}
	largePool = sync.Pool{New: func() any { b := make([]byte, LargeBufSize); return &b }}
)

// GetBuf returns a pooled buffer of at least size bytes with len == size.
// Buffers larger than LargeBufSize are allocated and never pooled.
// The caller must return it with PutBuf.
func GetBuf(size int) *[]byte {
	var bp *[]byte
	switch {
	case size <= SmallBufSize:
		bp = smallPool.Get().(*[]byte)
	case size <= LargeBufSize:
		bp = largePool.Get().(*[]byte)
	default:
		b := make([]byte, size)
		return &b
	}
	*bp = (*bp)[:size]
	return bp
}

// PutBuf returns a buffer obtained from GetBuf to its pool.
func PutBuf(bp *[]byte) {
	if bp == nil {
		return
	}
	switch cap(*bp) {
	case SmallBufSize:
		*bp = (*bp)[:SmallBufSize]
		smallPool.Put(bp)
	case LargeBufSize:
		*bp = (*bp)[:LargeBufSize]
		largePool.Put(bp)
	}
}
