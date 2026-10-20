package forwarder

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/frame"
	"marmot/internal/session"
)

// serveUDP carries one UDP flow: framed datagrams on the stream, plain
// datagrams to the target. PROXY v2 is not applied to UDP; the panels we
// target do not read it on UDP inbounds.
func (f *Forwarder) serveUDP(ctx context.Context, p *Policy, st session.Stream, target string) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", target)
	if err != nil {
		f.refuse(st, frame.ReplyUnreachable)
		return
	}
	if _, err := st.Write([]byte{frame.ReplyOK}); err != nil {
		_ = c.Close()
		_ = st.Close()
		return
	}

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	stop := func() {
		_ = c.Close()
		_ = st.Close()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop()
		buf := make([]byte, frame.MaxDatagram)
		for {
			n, err := frame.ReadDatagram(st, buf)
			if err != nil {
				return
			}
			touch()
			if _, err := c.Write(buf[:n]); err != nil {
				return
			}
			f.bytesIn.Add(int64(n))
		}
	}()

	defer wg.Wait()
	defer stop()
	buf := make([]byte, frame.MaxDatagram)
	scratch := make([]byte, 2+frame.MaxDatagram)
	idle := p.UDPIdleTimeout
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		n, err := c.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(0, last.Load())) < idle {
				continue // the other direction is still active
			}
			return
		}
		touch()
		if err := frame.WriteDatagram(st, scratch, buf[:n]); err != nil {
			return
		}
		f.bytesOut.Add(int64(n))
	}
}
