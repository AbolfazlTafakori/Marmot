package forwarder

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/session"
)

// errForbiddenDestination is returned when an exit stream asks for an
// address the exit node must never connect to (ADR-0010).
var errForbiddenDestination = errors.New("forwarder: destination not allowed for exit")

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// exitAllowed reports whether an exit stream may connect to ip: never to
// this host, private networks, link-local, CGNAT, unspecified, multicast
// or broadcast addresses.
func exitAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsLoopback(), ip.IsPrivate(), ip.IsUnspecified(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(), cgnat.Contains(ip):
		return false
	case ip.Is4() && (ip.As4()[0] == 0 || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255})):
		return false
	}
	return true
}

// isLocalAddr reports whether ip belongs to one of this host's interfaces,
// such as its public address: an exit must not reach the node's own
// services, whatever the port.
func isLocalAddr(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true // cannot tell, so refuse
	}
	ip = ip.Unmap()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if x, ok := netip.AddrFromSlice(n.IP); ok && x.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

// exitDestinationAllowed is the production rule for exit destinations.
func exitDestinationAllowed(ip netip.Addr) bool { return exitAllowed(ip) && !isLocalAddr(ip) }

// destinationRule returns the policy's rule for exit destinations.
func destinationRule(p *Policy) func(netip.Addr) bool {
	if p.AllowDestination != nil {
		return p.AllowDestination
	}
	return exitDestinationAllowed
}

// exitDialer checks every address it is about to connect to, after name
// resolution, so a domain cannot lead the exit into a forbidden range.
func exitDialer(allow func(netip.Addr) bool) *net.Dialer {
	return &net.Dialer{
		Timeout: DialTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allow(ap.Addr()) {
				return errForbiddenDestination
			}
			return nil
		},
	}
}

func destinationString(d frame.Destination) string {
	host := d.Host
	if d.IP.IsValid() {
		host = d.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(d.Port)))
}

// serveExit delivers an exit stream to its destination on the Internet.
// No PROXY header is written: the destination is not a panel inbound.
func (f *Forwarder) serveExit(ctx context.Context, p *Policy, st session.Stream, h frame.StreamHeader) {
	if !p.AllowExit {
		f.log.Warn("exit stream refused: this node's role does not allow exit")
		f.refuse(st, frame.ReplyDenied)
		return
	}
	allow := destinationRule(p)
	if h.Dest.IP.IsValid() && !allow(h.Dest.IP) {
		f.refuse(st, frame.ReplyDenied)
		return
	}
	network := "tcp"
	if h.Proto == core.ProtoUDP {
		network = "udp"
	}
	c, err := exitDialer(allow).DialContext(ctx, network, destinationString(h.Dest))
	if err != nil {
		f.log.Debug("exit dial failed", "network", network, "err", err)
		f.refuse(st, exitErrorCode(err))
		return
	}
	if h.Proto == core.ProtoUDP {
		f.pumpUDP(p, st, c)
		return
	}
	if _, err := st.Write([]byte{frame.ReplyOK}); err != nil {
		_ = c.Close()
		_ = st.Close()
		return
	}
	in, out := core.Pipe(st, c)
	f.bytesIn.Add(in)
	f.bytesOut.Add(out)
}

func exitErrorCode(err error) byte {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, errForbiddenDestination):
		return frame.ReplyDenied
	case errors.As(err, &dnsErr):
		return frame.ReplyUnreachable
	default:
		return dialErrorCode(err)
	}
}
