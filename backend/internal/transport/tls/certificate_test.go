package tls

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCertificateFromFiles(t *testing.T) {
	gen, err := selfSigned("panel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(gen.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gen.Certificate[0]}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)

	c, err := loadCertificate(map[string]any{"cert_file": certFile, "key_file": keyFile})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || leaf.Subject.CommonName != "panel.example.com" {
		t.Fatalf("leaf %v %v", leaf, err)
	}
	if _, err := loadCertificate(map[string]any{"cert_file": certFile, "key_file": certFile}); err == nil {
		t.Fatal("certificate accepted as key")
	}
	if _, err := loadCertificate(map[string]any{"key_file": 1}); err == nil {
		t.Fatal("non-string key_file accepted")
	}
}
