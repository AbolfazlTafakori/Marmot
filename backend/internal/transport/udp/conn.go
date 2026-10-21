package udp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/transport"
)

// conn is one peer of a udp socket: a handshake "stream" plus datagrams.
type conn struct {
	sock   *net.UDPConn
	raddr  netip.AddrPort
	own    bool        // the dialer's own socket: closed with the conn
	forget func(*conn) // the listener's table entry

	mu       sync.Mutex
	hs       [][]byte // handshake messages received, in order
	part     []byte   // the rest of a message being read
	recvSeq  int      // last handshake seq received, -1 none
	sendSeq  uint8
	lastHS   []byte // our last handshake datagram, resent until answered
	answered bool   // the peer answered (or records flow): stop resending
	hsReady  chan struct{}
	rdl      time.Time
	wdl      time.Time

	dg        chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	last      atomic.Int64 // unix nanoseconds of the last datagram received
}

var (
	_ transport.Conn         = (*conn)(nil)
	_ transport.Datagrammer  = (*conn)(nil)
	_ transport.DatagramOnly = (*conn)(nil)
	_ transport.Unpaced      = (*conn)(nil)
)

func newConn(sock *net.UDPConn, raddr netip.AddrPort, own bool, forget func(*conn)) *conn {
	c := &conn{sock: sock, raddr: raddr, own: own, forget: forget, recvSeq: -1,
		hsReady: make(chan struct{}, 1), dg: make(chan []byte, recvQueue), closed: make(chan struct{})}
	c.last.Store(time.Now().UnixNano())
	go c.resend()
	return c
}

// readOwn reads the dialer's own socket.
func (c *conn) readOwn() {
	buf := make([]byte, readBuf)
	for {
		n, from, err := c.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			c.end()
			return
		}
		if netip.AddrPortFrom(from.Addr().Unmap(), from.Port()) == c.raddr && n > 0 {
			c.receive(buf[:n])
		}
	}
}

// receive handles one datagram from the peer.
func (c *conn) receive(d []byte) {
	c.last.Store(time.Now().UnixNano())
	switch d[0] {
	case kindHandshake:
		if len(d) < 2 {
			return
		}
		seq := int(d[1])
		c.mu.Lock()
		switch {
		case seq == c.recvSeq:
			// The peer missed our answer: send it again.
			last := c.lastHS
			c.mu.Unlock()
			if last != nil {
				_ = c.send(last)
			}
			return
		case c.recvSeq >= 0 && seq != (c.recvSeq+1)%256:
			c.mu.Unlock()
			return
		}
		c.recvSeq = seq
		c.answered = true
		c.hs = append(c.hs, append([]byte(nil), d[2:]...))
		c.mu.Unlock()
		select {
		case c.hsReady <- struct{}{}:
		default:
		}
	case kindRecord:
		c.mu.Lock()
		c.answered = true
		c.mu.Unlock()
		select {
		case c.dg <- append([]byte(nil), d[1:]...):
		default: // the reader is behind: drop, as the network would
		}
	case kindClose:
		c.end()
	}
}

// resend repeats our last handshake datagram until the peer answers or
// the handshake time is over.
func (c *conn) resend() {
	t := time.NewTicker(hsRetry)
	defer t.Stop()
	deadline := time.After(hsTimeout)
	for {
		select {
		case <-c.closed:
			return
		case <-deadline:
			return
		case <-t.C:
		}
		c.mu.Lock()
		last, answered := c.lastHS, c.answered
		c.mu.Unlock()
		if last != nil && !answered {
			_ = c.send(last)
		}
	}
}

func (c *conn) send(b []byte) error {
	select {
	case <-c.closed:
		return errClosed
	default:
	}
	_, err := c.sock.WriteToUDPAddrPort(b, c.raddr)
	return err
}

// Read returns handshake bytes from the peer.
func (c *conn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.part) == 0 && len(c.hs) > 0 {
			c.part, c.hs = c.hs[0], c.hs[1:]
		}
		if len(c.part) > 0 {
			n := copy(b, c.part)
			c.part = c.part[n:]
			c.mu.Unlock()
			return n, nil
		}
		dl := c.rdl
		c.mu.Unlock()
		if err := c.waitHandshake(dl); err != nil {
			return 0, err
		}
	}
}

// waitHandshake waits for a handshake message, a deadline change or the
// end of the connection.
func (c *conn) waitHandshake(dl time.Time) error {
	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return errTimeout{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case <-c.hsReady:
		return nil
	case <-timeout:
		return errTimeout{}
	case <-c.closed:
		return errClosed
	}
}

// Write sends one handshake message; it is resent until answered.
func (c *conn) Write(b []byte) (int, error) {
	if len(b)+2 > maxDatagram {
		return 0, errTooLarge
	}
	c.mu.Lock()
	d := append([]byte{kindHandshake, c.sendSeq}, b...)
	c.sendSeq++
	c.lastHS, c.answered = d, false
	c.mu.Unlock()
	if err := c.send(d); err != nil {
		return 0, err
	}
	return len(b), nil
}

// SetDeadline bounds handshake reads (writes never block).
func (c *conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl, c.wdl = t, t
	c.mu.Unlock()
	select {
	case c.hsReady <- struct{}{}: // let a waiting Read see the new deadline
	default:
	}
	return nil
}

// Close tells the peer and ends the connection.
func (c *conn) Close() error {
	select {
	case <-c.closed:
	default:
		_ = c.send([]byte{kindClose})
	}
	c.end()
	return nil
}

func (c *conn) end() {
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.own {
			_ = c.sock.Close()
		}
		if c.forget != nil {
			c.forget(c)
		}
	})
}

func (c *conn) idle() time.Duration { return time.Since(time.Unix(0, c.last.Load())) }

func (c *conn) LocalAddr() net.Addr  { return c.sock.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.raddr) }

// DatagramsEnabled implements transport.Datagrammer.
func (c *conn) DatagramsEnabled() bool { return true }

// MaxDatagramSize implements transport.Datagrammer: one byte goes to the
// kind.
func (c *conn) MaxDatagramSize() int { return maxDatagram - 1 }

// SendDatagram implements transport.Datagrammer.
func (c *conn) SendDatagram(b []byte) error {
	if len(b) > c.MaxDatagramSize() {
		return errTooLarge
	}
	d := make([]byte, 1+len(b))
	d[0] = kindRecord
	copy(d[1:], b)
	return c.send(d)
}

// ReceiveDatagram implements transport.Datagrammer.
func (c *conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case d := <-c.dg:
		return d, nil
	case <-c.closed:
		return nil, errClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// DatagramOnly implements transport.DatagramOnly.
func (c *conn) DatagramOnly() {}

// Unpaced implements transport.Unpaced.
func (c *conn) Unpaced() {}

var errTooLarge = &net.OpError{Op: "write", Net: "udp", Err: errDatagramTooLarge{}}

type errDatagramTooLarge struct{}

func (errDatagramTooLarge) Error() string { return "datagram larger than 1,200 bytes" }
