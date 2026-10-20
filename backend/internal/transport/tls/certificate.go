package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"marmot/internal/transport"
)

// loadCertificate returns the configured certificate, or a fresh
// self-signed one when none is configured.
func loadCertificate(opts map[string]any) (stdtls.Certificate, error) {
	certFile, err := transport.StringOption(opts, "cert_file", "")
	if err != nil {
		return stdtls.Certificate{}, err
	}
	keyFile, err := transport.StringOption(opts, "key_file", "")
	if err != nil {
		return stdtls.Certificate{}, err
	}
	if (certFile == "") != (keyFile == "") {
		return stdtls.Certificate{}, fmt.Errorf("tls: set both cert_file and key_file, or neither")
	}
	if certFile != "" {
		c, err := stdtls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return stdtls.Certificate{}, fmt.Errorf("tls: load certificate: %w", err)
		}
		return c, nil
	}
	name, err := transport.StringOption(opts, "sni", "localhost")
	if err != nil {
		return stdtls.Certificate{}, err
	}
	return selfSigned(name)
}

func selfSigned(name string) (stdtls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return stdtls.Certificate{}, fmt.Errorf("tls: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return stdtls.Certificate{}, fmt.Errorf("tls: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return stdtls.Certificate{}, fmt.Errorf("tls: create certificate: %w", err)
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
