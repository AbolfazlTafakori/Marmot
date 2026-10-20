package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"marmot/internal/config"
)

// cmdHealth asks the running node's /readyz and exits non-zero unless it is
// ready. The container image has no shell or curl, so its HEALTHCHECK uses
// this.
func cmdHealth(args []string, out io.Writer) error {
	path, err := configFlag("health", args)
	if err != nil {
		return err
	}
	loaded, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	api := loaded.Config.API
	host, port, err := net.SplitHostPort(api.Listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if api.TLSCert != "" {
		scheme = "https"
		// Checking our own listener on loopback; the certificate is for the
		// public name, so it cannot verify here.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/readyz")
	if err != nil {
		return fmt.Errorf("not reachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s", resp.Status)
	}
	fmt.Fprintln(out, "ready")
	return nil
}
