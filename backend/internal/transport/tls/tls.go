// Package tls is the TCP+TLS transport. The client side uses uTLS so its
// ClientHello matches a common browser.
//
// TLS here is camouflage, not authentication: the peer is authenticated by
// the Noise IK handshake that runs inside, against a pinned key. That is why
// the client does not verify the server certificate and the server may use
// a self-signed one.
package tls

import (
	"context"
	stdtls "crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"time"

	utls "github.com/refraction-networking/utls"

	"marmot/internal/transport"
	"marmot/internal/transport/tcp"
)

// Name is the registered transport name.
const Name = "tls"

// handshakeTimeout bounds the TLS handshake of an accepted connection, so
// a silent client cannot hold a goroutine.
const handshakeTimeout = 10 * time.Second

func init() { transport.Register(Transport{}) }

// Transport is TLS over TCP.
//
// Endpoint options: sni (string), fingerprint (chrome | firefox | safari |
// edge | ios | randomized | go; default chrome).
// Listen options: cert_file, key_file (strings; default a self-signed
// certificate for sni or "localhost").
type Transport struct{}

// Name implements transport.Transport.
func (Transport) Name() string { return Name }

// Kind implements transport.Transport.
func (Transport) Kind() transport.Kind { return transport.Stream }

var fingerprints = map[string]utls.ClientHelloID{
	"chrome":     utls.HelloChrome_Auto,
	"firefox":    utls.HelloFirefox_Auto,
	"safari":     utls.HelloSafari_Auto,
	"edge":       utls.HelloEdge_Auto,
	"ios":        utls.HelloIOS_Auto,
	"randomized": utls.HelloRandomized,
	"go":         utls.HelloGolang,
}

// Dial implements transport.Transport.
func (Transport) Dial(ctx context.Context, ep transport.Endpoint, local netip.Addr) (transport.Conn, error) {
	sni, err := transport.StringOption(ep.Options, "sni", "")
	if err != nil {
		return nil, err
	}
	fpName, err := transport.StringOption(ep.Options, "fingerprint", "chrome")
	if err != nil {
		return nil, err
	}
	fp, ok := fingerprints[fpName]
	if !ok {
		return nil, fmt.Errorf("tls: unknown fingerprint %q", fpName)
	}
	raw, err := tcp.DialTCP(ctx, ep.Addr, local)
	if err != nil {
		return nil, err
	}
	uc := utls.UClient(raw, &utls.Config{
		ServerName: sni,
		// See the package comment: Noise authenticates the peer.
		InsecureSkipVerify: true,
	}, fp)
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake %s: %w", ep.Addr, err)
	}
	return uc, nil
}

// Listen implements transport.Transport.
func (Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	cert, err := loadCertificate(cfg.Options)
	if err != nil {
		return nil, err
	}
	l, err := tcp.ListenTCP(ctx, cfg.Addr)
	if err != nil {
		return nil, err
	}
	conf := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	return &listener{TCPListener: l, conf: conf}, nil
}

type listener struct {
	*net.TCPListener
	conf *stdtls.Config
}

// Accept returns the connection before the TLS handshake runs; the
// handshake happens on first Read/Write, so one slow client never blocks
// the accept loop. Its deadline is set here and cleared by the session
// layer after the Noise handshake.
func (l *listener) Accept() (transport.Conn, error) {
	c, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = c.SetNoDelay(true)
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	return stdtls.Server(c, l.conf), nil
}
