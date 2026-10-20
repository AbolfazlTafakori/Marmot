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
	raw, err := tcp.DialTCP(ctx, ep.Addr, local)
	if err != nil {
		return nil, err
	}
	uc, err := Client(ctx, raw, ep.Options, nil)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake %s: %w", ep.Addr, err)
	}
	return uc, nil
}

// Client runs a uTLS client handshake on raw with the endpoint options sni
// and fingerprint. alpn, when set, replaces the fingerprint's ALPN list
// (ws needs http/1.1 only, grpc h2 only). Other transports that run over
// TLS use it. raw is not closed on error.
func Client(ctx context.Context, raw net.Conn, opts map[string]any, alpn []string) (*utls.UConn, error) {
	sni, err := transport.StringOption(opts, "sni", "")
	if err != nil {
		return nil, err
	}
	fpName, err := transport.StringOption(opts, "fingerprint", "chrome")
	if err != nil {
		return nil, err
	}
	fp, ok := fingerprints[fpName]
	if !ok {
		return nil, fmt.Errorf("tls: unknown fingerprint %q", fpName)
	}
	conf := &utls.Config{
		ServerName: sni,
		// See the package comment: Noise authenticates the peer.
		InsecureSkipVerify: true,
	}
	var uc *utls.UConn
	if alpn == nil {
		uc = utls.UClient(raw, conf, fp)
	} else {
		spec, err := utls.UTLSIdToSpec(fp)
		if err != nil {
			return nil, fmt.Errorf("tls: fingerprint %q: %w", fpName, err)
		}
		setALPN(&spec, alpn)
		uc = utls.UClient(raw, conf, utls.HelloCustom)
		if err := uc.ApplyPreset(&spec); err != nil {
			return nil, fmt.Errorf("tls: fingerprint %q: %w", fpName, err)
		}
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uc, nil
}

// setALPN replaces the ALPN list of spec, adding the extension if the
// fingerprint has none.
func setALPN(spec *utls.ClientHelloSpec, alpn []string) {
	for _, e := range spec.Extensions {
		if a, ok := e.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = alpn
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: alpn})
}

// ServerConfig returns the server TLS config from listen options
// cert_file, key_file and sni (see loadCertificate), offering nextProtos.
func ServerConfig(opts map[string]any, nextProtos []string) (*stdtls.Config, error) {
	cert, err := loadCertificate(opts)
	if err != nil {
		return nil, err
	}
	return &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS12,
		NextProtos:   nextProtos,
	}, nil
}

// Listen implements transport.Transport.
func (Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	conf, err := ServerConfig(cfg.Options, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}
	l, err := tcp.ListenTCP(ctx, cfg.Addr)
	if err != nil {
		return nil, err
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
