// Package cache keeps hot links in Redis so redirects skip Postgres, and
// provides a fixed-window rate limiter.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/doppIer/shrink-it/internal/store"
)

type Cache struct {
	rdb *redis.Client
	ttl time.Duration
}

func New(redisURL string, ttl time.Duration) (*Cache, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &Cache{rdb: redis.NewClient(opt), ttl: ttl}, nil
}

func (c *Cache) Close() error                   { return c.rdb.Close() }
func (c *Cache) Ping(ctx context.Context) error { return c.rdb.Ping(ctx).Err() }

func key(code string) string { return "link:" + code }

// cachedLink includes the ID, which store.Link hides from API JSON.
type cachedLink struct {
	ID int64 `json:"id"`
	*store.Link
}

func (c *Cache) Set(ctx context.Context, l *store.Link) {
	b, err := json.Marshal(cachedLink{ID: l.ID, Link: l})
	if err == nil {
		c.rdb.Set(ctx, key(l.Code), b, c.ttl)
	}
}

func (c *Cache) GetLink(ctx context.Context, code string) (*store.Link, bool) {
	b, err := c.rdb.Get(ctx, key(code)).Bytes()
	if err != nil {
		return nil, false
	}
	var cl cachedLink
	cl.Link = &store.Link{}
	if json.Unmarshal(b, &cl) != nil {
		return nil, false
	}
	cl.Link.ID = cl.ID
	return cl.Link, true
}

func (c *Cache) Delete(ctx context.Context, code string) {
	c.rdb.Del(ctx, key(code))
}

// Allow implements a fixed-window counter: at most limit hits per window.
func (c *Cache) Allow(ctx context.Context, bucket string, limit int, window time.Duration) (bool, error) {
	k := "rl:" + bucket + ":" + time.Now().Truncate(window).Format("200601021504")
	pipe := c.rdb.TxPipeline()
	incr := pipe.Incr(ctx, k)
	pipe.Expire(ctx, k, window)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return true, err // fail open: Redis hiccups shouldn't break the API
	}
	return incr.Val() <= int64(limit), nil
}
