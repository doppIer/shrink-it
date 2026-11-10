// Command server runs the shrink-it HTTP server and its background workers.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/doppIer/shrink-it/internal/analytics"
	"github.com/doppIer/shrink-it/internal/cache"
	"github.com/doppIer/shrink-it/internal/config"
	"github.com/doppIer/shrink-it/internal/health"
	"github.com/doppIer/shrink-it/internal/httpapi"
	"github.com/doppIer/shrink-it/internal/safety"
	"github.com/doppIer/shrink-it/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	c, err := cache.New(cfg.RedisURL, cfg.CacheTTL)
	if err != nil {
		return err
	}
	defer c.Close()

	scanner := buildScanner(cfg, log)

	rec := analytics.NewRecorder(st, log)
	go rec.Run(ctx)

	worker := &health.Worker{
		Store: st, Cache: c, Scanner: scanner, Client: health.NewClient(cfg.AllowPrivateTargets),
		Interval: cfg.HealthInterval, FailThreshold: cfg.HealthFailThreshold, BatchSize: cfg.HealthBatchSize, Log: log,
	}
	go worker.Run(ctx)

	if cfg.AdminToken == "" {
		log.Warn("ADMIN_TOKEN is empty: the management API is open to anyone who can reach it")
	}
	api := &httpapi.Server{
		Store: st, Cache: c, Scanner: scanner, Recorder: rec, Log: log,
		BaseURL: cfg.BaseURL, AdminToken: cfg.AdminToken, TrustProxy: cfg.TrustProxy, CreateRateLimit: cfg.CreateRateLimit,
	}
	srv := &http.Server{
		Addr: cfg.Addr, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr, "base_url", cfg.BaseURL, "version", version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	stop()
	rec.Wait() // flush buffered clicks before closing the DB pool
	return err
}

func buildScanner(cfg config.Config, log *slog.Logger) safety.Scanner {
	checkers := []safety.Checker{
		safety.NetworkPolicy{AllowPrivate: cfg.AllowPrivateTargets},
		safety.Heuristics{},
	}
	if cfg.BlocklistPath != "" {
		bl, err := safety.LoadBlocklist(cfg.BlocklistPath)
		if err != nil {
			log.Warn("could not load blocklist", "path", cfg.BlocklistPath, "err", err)
		} else {
			log.Info("blocklist loaded", "domains", bl.Len())
			checkers = append(checkers, bl)
		}
	}
	if cfg.SafeBrowsingKey != "" {
		checkers = append(checkers, &safety.SafeBrowsing{APIKey: cfg.SafeBrowsingKey, Client: &http.Client{Timeout: 3 * time.Second}})
		log.Info("google safe browsing enabled")
	}
	return safety.Scanner{Checkers: checkers}
}
