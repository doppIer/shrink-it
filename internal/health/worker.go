// Package health periodically probes link targets, marks dead ones as
// broken (so redirects switch to the fallback URL) and re-runs the safety
// scan, because a domain that was clean last week can be compromised today.
package health

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/doppIer/shrink-it/internal/safety"
	"github.com/doppIer/shrink-it/internal/store"
)

const (
	StatusHealthy = "healthy"
	StatusBroken  = "broken"
)

type Store interface {
	DueForCheck(ctx context.Context, before time.Time, limit int) ([]*store.Link, error)
	UpdateHealth(ctx context.Context, id int64, status string, statusCode, failures int, at time.Time) error
	UpdateSafety(ctx context.Context, id int64, status, reason string, warnings []string) error
}

type Invalidator interface {
	Delete(ctx context.Context, code string)
}

type Worker struct {
	Store         Store
	Cache         Invalidator
	Scanner       safety.Scanner
	Client        *http.Client
	Interval      time.Duration
	FailThreshold int
	BatchSize     int
	Log           *slog.Logger
}

// NewClient returns an HTTP client whose dialer refuses private addresses,
// closing the DNS-rebinding gap between "scan at create time" and "probe now".
func NewClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !safety.IsPublic(ip) {
				return errors.New("refusing to connect to non-public address " + host)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: 8 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func (w *Worker) Run(ctx context.Context) {
	w.tick(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	links, err := w.Store.DueForCheck(ctx, time.Now().Add(-w.Interval), w.BatchSize)
	if err != nil {
		if ctx.Err() == nil {
			w.Log.Error("health: load due links", "err", err)
		}
		return
	}
	for _, l := range links {
		if ctx.Err() != nil {
			return
		}
		w.CheckLink(ctx, l)
	}
}

// CheckLink probes one link and persists the result.
func (w *Worker) CheckLink(ctx context.Context, l *store.Link) {
	code, ok := w.Probe(ctx, l.TargetURL)
	failures := 0
	if !ok {
		failures = l.ConsecutiveFailures + 1
	}
	// A single failed probe isn't enough to change state: keep the previous
	// status until the failure threshold is reached.
	status := l.HealthStatus
	switch {
	case ok:
		status = StatusHealthy
	case failures >= w.FailThreshold:
		status = StatusBroken
	}
	if err := w.Store.UpdateHealth(ctx, l.ID, status, code, failures, time.Now()); err != nil {
		w.Log.Error("health: update", "code", l.Code, "err", err)
		return
	}
	if u, err := url.Parse(l.TargetURL); err == nil {
		v := w.Scanner.Scan(ctx, u)
		safetyStatus := "safe"
		if !v.Safe {
			safetyStatus = "flagged"
		}
		if safetyStatus != l.SafetyStatus {
			w.Log.Warn("health: safety status changed", "code", l.Code, "from", l.SafetyStatus, "to", safetyStatus, "reason", v.Reason)
		}
		_ = w.Store.UpdateSafety(ctx, l.ID, safetyStatus, v.Reason, v.Warnings)
	}
	if status != l.HealthStatus {
		w.Log.Info("health: status changed", "code", l.Code, "from", l.HealthStatus, "to", status, "http_status", code)
	}
	w.Cache.Delete(ctx, l.Code)
}

// Probe tries HEAD first and falls back to GET for servers that reject HEAD.
// Any status below 400 counts as healthy.
func (w *Worker) Probe(ctx context.Context, target string) (int, bool) {
	code, err := w.do(ctx, http.MethodHead, target)
	if err != nil || code == http.StatusMethodNotAllowed || code == http.StatusNotImplemented || code == http.StatusForbidden {
		code, err = w.do(ctx, http.MethodGet, target)
	}
	if err != nil {
		return 0, false
	}
	return code, code < 400
}

func (w *Worker) do(ctx context.Context, method, target string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "shrink-it-healthcheck/0.1 (+https://github.com/doppIer/shrink-it)")
	resp, err := w.Client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
