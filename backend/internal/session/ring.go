package session

// ring is a byte FIFO over a circular buffer. It is not safe for concurrent
// use; ResumableConn guards it with its mutex.
//
// A ring with max > cap grows on demand (receive side); one with
// max == cap never grows and Write reports how much fit (send side).
type ring struct {
	buf  []byte
	head int // index of the first byte
	n    int // number of bytes held
	max  int
}

func newRing(initial, max int) *ring {
	return &ring{buf: make([]byte, initial), max: max}
}

func (r *ring) Len() int  { return r.n }
func (r *ring) Free() int { return r.max - r.n }

// Write appends as much of p as fits within max and returns the count.
func (r *ring) Write(p []byte) int {
	if want := r.n + len(p); want > len(r.buf) && len(r.buf) < r.max {
		r.grow(want)
	}
	k := min(len(p), len(r.buf)-r.n)
	tail := (r.head + r.n) % len(r.buf)
	c := copy(r.buf[tail:], p[:k])
	copy(r.buf, p[c:k])
	r.n += k
	return k
}

func (r *ring) grow(want int) {
	size := max(2*len(r.buf), want)
	size = min(size, r.max)
	nb := make([]byte, size)
	r.copyOut(nb, 0, r.n)
	r.buf, r.head = nb, 0
}

// Read removes up to len(p) bytes from the front into p.
func (r *ring) Read(p []byte) int {
	k := min(len(p), r.n)
	r.copyOut(p, 0, k)
	r.Discard(k)
	return k
}

// Discard drops k bytes from the front.
func (r *ring) Discard(k int) {
	r.n -= k
	if r.n == 0 {
		r.head = 0
		return
	}
	r.head = (r.head + k) % len(r.buf)
}

// AppendRange appends k bytes starting at offset off from the front to dst,
// without removing them.
func (r *ring) AppendRange(dst []byte, off, k int) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, k)...)[:start+k]
	r.copyOut(dst[start:], off, k)
	return dst
}

func (r *ring) copyOut(dst []byte, off, k int) {
	if k == 0 {
		return
	}
	i := (r.head + off) % len(r.buf)
	c := copy(dst[:k], r.buf[i:])
	copy(dst[c:k], r.buf)
}
