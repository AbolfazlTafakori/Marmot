package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"marmot/internal/api"
	"marmot/internal/config"
	"marmot/internal/crypto"
	"marmot/internal/node"
	"marmot/internal/store"
	"marmot/internal/telemetry"
	"marmot/internal/transport"
)

// cmdRun runs the node, the panel API and the metrics endpoint until
// SIGINT or SIGTERM. SIGHUP re-reads the configuration file.
func cmdRun(args []string) error {
	path, err := configFlag("run", args)
	if err != nil {
		return err
	}
	if err := transport.Check(); err != nil {
		return err
	}
	loaded, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	cfg := loaded.Config
	level := new(slog.LevelVar)
	setLevel(level, cfg.Telemetry.LogLevel)
	log, logs := telemetry.NewLogger(os.Stderr, level, slog.LevelWarn)
	for _, w := range loaded.Warnings {
		log.Warn("config warning", "path", w.Path, "detail", w.Message)
	}
	if limit := telemetry.ApplyMemoryLimit(); limit > 0 {
		log.Info("memory limit from cgroup", "bytes", limit)
	}

	id, err := crypto.LoadIdentity(cfg.Node.IdentityKeyFile)
	if err != nil {
		return fmt.Errorf("%w (create one with: marmot keygen -out %s)", err, cfg.Node.IdentityKeyFile)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.API.DataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if n, err := st.CountAdmins(ctx); err == nil && n == 0 {
		log.Warn("no panel administrators yet; create one with: marmot admin create -config " + path + " -username NAME")
	}

	n, err := node.New(cfg, id, node.Options{Version: version, Logger: log})
	if err != nil {
		return err
	}
	if err := n.Start(); err != nil {
		return err
	}
	srv, err := api.New(api.Config{Node: n, Store: st, ConfigPath: path, Logs: logs,
		Logger: log.With("component", "api"), Version: version})
	if err != nil {
		_ = n.Stop()
		return err
	}

	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Run(ctx); err != nil {
			errc <- fmt.Errorf("panel api: %w", err)
		}
	}()
	if addr := cfg.Telemetry.MetricsListen; addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serveMetrics(ctx, addr, n, log); err != nil {
				errc <- fmt.Errorf("metrics: %w", err)
			}
		}()
	}

	events, unsubscribe := n.Subscribe()
	defer unsubscribe()
	reload := reloadSignal()
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case runErr = <-errc:
			stop()
			break loop
		case e := <-events:
			// The panel can change the log level; follow it.
			if e.Type == node.EventConfigApplied {
				setLevel(level, n.Config().Telemetry.LogLevel)
			}
		case <-reload:
			l, err := config.LoadFile(path)
			if err != nil {
				log.Error("reload rejected; keeping the running config", "err", err)
				continue
			}
			if err := n.Reload(l.Config); err != nil {
				log.Error("reload applied with errors", "err", err)
			}
		}
	}
	wg.Wait()
	if err := n.Stop(); err != nil && !errors.Is(err, node.ErrNotRunning) {
		return err
	}
	return runErr
}

// serveMetrics serves Prometheus metrics on their own listener, so the
// panel port never exposes them.
func serveMetrics(ctx context.Context, addr string, n *node.Node, log *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", telemetry.Handler(func() []telemetry.Metric { return api.Metrics(n) }))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("metrics listening", "addr", ln.Addr().String())
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-errc:
		return err
	}
}

func setLevel(v *slog.LevelVar, s string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err == nil {
		v.Set(l)
	}
}
