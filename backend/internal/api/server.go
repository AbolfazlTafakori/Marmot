// Package api is the panel's HTTP API (backend/api/openapi.yaml): REST under
// /api/v1, live events over WebSocket, and the static panel files.
package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"marmot/internal/node"
	"marmot/internal/store"
	"marmot/internal/telemetry"
)

// Config holds what the API needs. Node, Store and ConfigPath are required.
type Config struct {
	Node       *node.Node
	Store      *store.Store
	ConfigPath string // marmot.toml, read and written by the config endpoints
	Logs       *telemetry.LogHub
	Logger     *slog.Logger
	Version    string
}

// Login limits: per client address and per username, so neither a single
// address nor a botnet aimed at one account gets many guesses.
const (
	loginWindow       = 10 * time.Minute
	loginLimitPerIP   = 10
	loginLimitPerUser = 5
	maintenanceEvery  = 10 * time.Minute
	shutdownGrace     = 5 * time.Second
	readHeaderTimeout = 10 * time.Second
)

// Server serves the panel API.
type Server struct {
	cfg       Config
	log       *slog.Logger
	handler   http.Handler
	loginIP   *rateLimiter
	loginUser *rateLimiter
	traffic   *trafficSampler
	now       func() time.Time

	cfgMu sync.Mutex // serialises writes of marmot.toml
}

// New builds the server and its routes.
func New(cfg Config) (*Server, error) {
	if cfg.Node == nil || cfg.Store == nil || cfg.ConfigPath == "" {
		return nil, errors.New("api: node, store and config path are required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		cfg:       cfg,
		log:       log,
		loginIP:   newRateLimiter(loginLimitPerIP, loginWindow),
		loginUser: newRateLimiter(loginLimitPerUser, loginWindow),
		now:       time.Now,
	}
	s.traffic = newTrafficSampler(cfg.Node, cfg.Store, log)
	s.handler = s.routes()
	return s, nil
}

// Handler returns the root handler (API, WebSocket and static files).
func (s *Server) Handler() http.Handler { return s.handler }

// Run serves on api.listen until ctx ends, then shuts down gracefully. It
// also runs the traffic sampler and periodic clean-up.
func (s *Server) Run(ctx context.Context) error {
	api := s.cfg.Node.Config().API
	ln, err := net.Listen("tcp", api.Listen)
	if err != nil {
		return fmt.Errorf("api listen %s: %w", api.Listen, err)
	}
	if api.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(api.TLSCert, api.TLSKey)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("api tls: %w", err)
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	return s.serve(ctx, ln)
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.traffic.run(ctx)
	}()
	go func() {
		defer wg.Done()
		s.maintain(ctx)
	}()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	s.log.Info("panel api listening", "addr", ln.Addr().String())

	var err error
	select {
	case <-ctx.Done():
		// The parent is already cancelled; shutdown still needs its grace period.
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		err = srv.Shutdown(sctx)
		cancel()
		if serr := <-errc; err == nil && !errors.Is(serr, http.ErrServerClosed) {
			err = serr
		}
	case err = <-errc:
	}
	wg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// maintain purges expired sessions and forgotten rate-limit entries.
func (s *Server) maintain(ctx context.Context) {
	t := time.NewTicker(maintenanceEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.cfg.Store.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("purge sessions", "err", err)
		}
		s.loginIP.sweep()
		s.loginUser.sweep()
	}
}
