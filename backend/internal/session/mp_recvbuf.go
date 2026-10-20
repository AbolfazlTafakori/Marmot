package session

// recvBuf holds the received bytes of one v2 stream from the reader's
// offset upward, in or out of order. Positions are offsets relative to
// the read offset; the buffer grows on demand up to max, which flow
// control guarantees is never exceeded.
type recvBuf struct {
	buf   []byte // circular; index start holds the byte at the read offset
	start int
	have  rangeSet // absolute offsets received and not yet read
	max   int
}

const recvBufInitial = 16 << 10

// write stores data at absolute offset off; readOff is the reader's
// offset. The caller has dropped any part below readOff and checked that
// off+len(data) <= readOff+max.
func (r *recvBuf) write(readOff, off uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	rel := int(off - readOff)
	r.ensure(rel + len(data))
	n := len(r.buf)
	i := (r.start + rel) % n
	c := copy(r.buf[i:], data)
	copy(r.buf, data[c:])
	r.have.add(off, off+uint64(len(data)))
}

// contiguous is how many bytes can be read now.
func (r *recvBuf) contiguous(readOff uint64) int {
	f, ok := r.have.first()
	if !ok || f.lo > readOff {
		return 0
	}
	return int(f.hi - readOff)
}

// read copies up to len(p) contiguous bytes and returns the count; the
// caller advances its read offset by it.
func (r *recvBuf) read(readOff uint64, p []byte) int {
	k := min(len(p), r.contiguous(readOff))
	if k == 0 {
		return 0
	}
	n := len(r.buf)
	c := copy(p[:k], r.buf[r.start:])
	copy(p[c:k], r.buf)
	r.start = (r.start + k) % n
	r.have.trimBelow(readOff + uint64(k))
	return k
}

// discard drops everything held.
func (r *recvBuf) discard() {
	r.buf, r.start = nil, 0
	r.have = rangeSet{}
}

// ensure grows the buffer to hold need bytes from the read offset.
func (r *recvBuf) ensure(need int) {
	if need <= len(r.buf) {
		return
	}
	size := max(2*len(r.buf), need, recvBufInitial)
	if r.max > 0 {
		size = min(size, max(r.max, need))
	}
	nb := make([]byte, size)
	if n := len(r.buf); n > 0 {
		c := copy(nb, r.buf[r.start:])
		copy(nb[c:], r.buf[:r.start])
	}
	r.buf, r.start = nb, 0
}
