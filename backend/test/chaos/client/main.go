// Command chaos-client streams a deterministic byte sequence through a tunneled port to an
// echo server behind it, verifies every byte that comes back, and reports
// the longest stall. It exits non-zero on corruption or a broken stream.
package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	echo := flag.String("echo", "127.0.0.1:23000", "echo server listen address")
	via := flag.String("via", "127.0.0.1:22052", "tunneled port to dial")
	dur := flag.Duration("for", 20*time.Second, "how long to send")
	rate := flag.Int("rate", 4<<20, "bytes per second to send")
	flag.Parse()

	l, err := net.Listen("tcp", *echo)
	if err != nil {
		fail("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	c, err := net.Dial("tcp", *via)
	if err != nil {
		fail("dial tunnel: %v", err)
	}
	var sent atomic.Int64
	done := make(chan struct{})
	go func() {
		src := rand.New(rand.NewSource(42))
		buf := make([]byte, 16<<10)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		end := time.Now().Add(*dur)
		perTick := *rate / 100
		for time.Now().Before(end) {
			<-tick.C
			for n := 0; n < perTick; n += len(buf) {
				src.Read(buf)
				if _, err := c.Write(buf); err != nil {
					fail("write after %d bytes: %v", sent.Load(), err)
				}
				sent.Add(int64(len(buf)))
			}
		}
		close(done)
	}()

	check := rand.New(rand.NewSource(42))
	want := make([]byte, 64<<10)
	got := make([]byte, 64<<10)
	var recv int64
	var maxStall time.Duration
	last := time.Now()
	start := last
	for {
		select {
		case <-done:
			if recv == sent.Load() {
				fmt.Printf("OK: %d MiB verified in %s, longest stall %s\n",
					recv>>20, time.Since(start).Round(time.Millisecond), maxStall.Round(time.Millisecond))
				return
			}
		default:
		}
		_ = c.SetReadDeadline(time.Now().Add(45 * time.Second))
		n, err := c.Read(got)
		if err != nil {
			fail("read after %d bytes: %v", recv, err)
		}
		if s := time.Since(last); s > maxStall {
			maxStall = s
		}
		last = time.Now()
		check.Read(want[:n])
		for i := 0; i < n; i++ {
			if got[i] != want[i] {
				fail("CORRUPT at byte %d", recv+int64(i))
			}
		}
		recv += int64(n)
	}
}

func fail(format string, a ...any) {
	fmt.Printf("FAIL: "+format+"\n", a...)
	os.Exit(1)
}
