package health

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/doppIer/shrink-it/internal/safety"
	"github.com/doppIer/shrink-it/internal/store"
)

type fakeStore struct {
	status   string
	failures int
}

func (f *fakeStore) DueForCheck(context.Context, time.Time, int) ([]*store.Link, error) {
	return nil, nil
}
func (f *fakeStore) UpdateHealth(_ context.Context, _ int64, status string, _, failures int, _ time.Time) error {
	f.status, f.failures = status, failures
	return nil
}
func (f *fakeStore) UpdateSafety(context.Context, int64, string, string, []string) error { return nil }

type nopCache struct{}

func (nopCache) Delete(context.Context, string) {}

func TestCheckLinkMarksBrokenAfterThreshold(t *testing.T) {
	healthy := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed) // force GET fallback
			return
		}
		if !healthy {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	fs := &fakeStore{}
	w := &Worker{Store: fs, Cache: nopCache{}, Scanner: safety.Scanner{}, Client: NewClient(true), FailThreshold: 3,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	link := &store.Link{ID: 1, Code: "x", TargetURL: srv.URL, HealthStatus: "unknown"}

	w.CheckLink(context.Background(), link)
	if fs.status != StatusHealthy || fs.failures != 0 {
		t.Fatalf("expected healthy, got %s/%d", fs.status, fs.failures)
	}

	healthy = false
	for i := 1; i <= 3; i++ {
		link.ConsecutiveFailures, link.HealthStatus = fs.failures, fs.status
		w.CheckLink(context.Background(), link)
		if fs.failures != i {
			t.Fatalf("failures=%d want %d", fs.failures, i)
		}
		if i < 3 && fs.status != StatusHealthy {
			t.Fatalf("status flipped to %s after only %d failures", fs.status, i)
		}
	}
	if fs.status != StatusBroken {
		t.Fatalf("expected broken after 3 failures, got %s", fs.status)
	}

	healthy = true
	link.ConsecutiveFailures, link.HealthStatus = fs.failures, fs.status
	w.CheckLink(context.Background(), link)
	if fs.status != StatusHealthy {
		t.Fatalf("expected recovery, got %s", fs.status)
	}
}

func TestClientBlocksPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	w := &Worker{Client: NewClient(false)}
	if _, ok := w.Probe(context.Background(), srv.URL); ok {
		t.Fatal("expected loopback probe to be refused")
	}
}
