// Package analytics buffers click events and writes them to Postgres in
// batches, so the redirect hot path never waits on a database insert.
package analytics

import (
	"context"
	"log/slog"
	"time"

	"github.com/doppIer/shrink-it/internal/store"
)

type Sink interface {
	InsertClicks(ctx context.Context, clicks []store.Click) error
}

type Recorder struct {
	sink       Sink
	ch         chan store.Click
	batchSize  int
	flushEvery time.Duration
	log        *slog.Logger
	done       chan struct{}
}

func NewRecorder(sink Sink, log *slog.Logger) *Recorder {
	return &Recorder{sink: sink, ch: make(chan store.Click, 10_000), batchSize: 500, flushEvery: 2 * time.Second, log: log, done: make(chan struct{})}
}

// Record never blocks; if the buffer is full the event is dropped.
func (r *Recorder) Record(c store.Click) {
	select {
	case r.ch <- c:
	default:
		r.log.Warn("click buffer full, dropping event")
	}
}

// Run flushes until ctx is cancelled, then drains what's left.
func (r *Recorder) Run(ctx context.Context) {
	defer close(r.done)
	t := time.NewTicker(r.flushEvery)
	defer t.Stop()
	batch := make([]store.Click, 0, r.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := r.sink.InsertClicks(fctx, batch); err != nil {
			r.log.Error("insert clicks", "err", err, "count", len(batch))
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case c := <-r.ch:
			batch = append(batch, c)
			if len(batch) >= r.batchSize {
				flush()
			}
		case <-t.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case c := <-r.ch:
					batch = append(batch, c)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Wait blocks until Run has drained after shutdown.
func (r *Recorder) Wait() { <-r.done }
