package analytics

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/doppIer/shrink-it/internal/store"
)

type memSink struct {
	mu sync.Mutex
	n  int
}

func (m *memSink) InsertClicks(_ context.Context, c []store.Click) error {
	m.mu.Lock()
	m.n += len(c)
	m.mu.Unlock()
	return nil
}

func TestRecorderDrainsOnShutdown(t *testing.T) {
	sink := &memSink{}
	r := NewRecorder(sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.flushEvery = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	for i := 0; i < 1234; i++ {
		r.Record(store.Click{LinkID: 1})
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	r.Wait()
	if sink.n != 1234 {
		t.Fatalf("recorded %d clicks, want 1234", sink.n)
	}
}
