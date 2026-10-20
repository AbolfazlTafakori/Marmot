package core

import (
	"io"
	"sync"
)

// Pipe copies bytes both ways between a and b until either direction ends,
// then closes both and returns the byte counts. Streams in session v1 have
// no half-close, so the end of one direction ends the connection; data
// already written is still delivered in order before the close.
//
// io.CopyBuffer prefers WriterTo/ReaderFrom, so TCP to TCP uses splice on
// Linux; otherwise one pooled buffer per direction is used.
func Pipe(a, b io.ReadWriteCloser) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bToA = copyPooled(a, b)
		_ = a.Close()
		_ = b.Close()
	}()
	aToB = copyPooled(b, a)
	_ = a.Close()
	_ = b.Close()
	wg.Wait()
	return aToB, bToA
}

func copyPooled(dst io.Writer, src io.Reader) int64 {
	bp := GetBuf(LargeBufSize)
	defer PutBuf(bp)
	n, _ := io.CopyBuffer(dst, src, *bp)
	return n
}
