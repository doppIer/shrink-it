// Package store is the PostgreSQL persistence layer.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/doppIer/shrink-it/internal/rules"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrCodeTaken = errors.New("code already taken")
	//go:embed migrations/*.sql
	migrationsFS embed.FS
)

type Link struct {
	ID                  int64      `json:"-"`
	Code                string     `json:"code"`
	TargetURL           string     `json:"url"`
	FallbackURL         string     `json:"fallback_url,omitempty"`
	Rules               rules.Set  `json:"rules"`
	SafetyStatus        string     `json:"safety_status"`
	SafetyReason        string     `json:"safety_reason,omitempty"`
	SafetyWarnings      []string   `json:"safety_warnings"`
	HealthStatus        string     `json:"health_status"`
	LastStatusCode      int        `json:"last_status_code,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	Disabled            bool       `json:"disabled"`
	CreatedAt           time.Time  `json:"created_at"`
}

func (l *Link) Expired(now time.Time) bool { return l.ExpiresAt != nil && now.After(*l.ExpiresAt) }

type Click struct {
	LinkID       int64
	At           time.Time
	Device       string
	Country      string
	ReferrerHost string
	TargetURL    string
	Reason       string
}

type Store struct{ db *pgxpool.Pool }

func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	// Postgres may still be starting when the container boots.
	for i := 0; ; i++ {
		if err = pool.Ping(ctx); err == nil {
			break
		}
		if i == 20 {
			pool.Close()
			return nil, fmt.Errorf("postgres not reachable: %w", err)
		}
		time.Sleep(time.Second)
	}
	return &Store{db: pool}, nil
}

func (s *Store) Close()                         { s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.Ping(ctx) }

// Migrate applies embedded SQL migrations in filename order, once each.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var exists bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, _ := migrationsFS.ReadFile(name)
		err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES ($1)`, name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

const linkColumns = `id, code, target_url, COALESCE(fallback_url,''), rules, safety_status, COALESCE(safety_reason,''),
	safety_warnings, health_status, COALESCE(last_status_code,0), consecutive_failures, last_checked_at, expires_at, disabled, created_at`

func scanLink(row pgx.Row) (*Link, error) {
	var l Link
	var rulesJSON, warningsJSON []byte
	err := row.Scan(&l.ID, &l.Code, &l.TargetURL, &l.FallbackURL, &rulesJSON, &l.SafetyStatus, &l.SafetyReason,
		&warningsJSON, &l.HealthStatus, &l.LastStatusCode, &l.ConsecutiveFailures, &l.LastCheckedAt, &l.ExpiresAt, &l.Disabled, &l.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rulesJSON, &l.Rules); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(warningsJSON, &l.SafetyWarnings); err != nil {
		return nil, err
	}
	if l.SafetyWarnings == nil {
		l.SafetyWarnings = []string{}
	}
	return &l, nil
}

func (s *Store) Create(ctx context.Context, l *Link) error {
	rulesJSON, _ := json.Marshal(l.Rules)
	warnings := l.SafetyWarnings
	if warnings == nil {
		warnings = []string{}
	}
	warningsJSON, _ := json.Marshal(warnings)
	row := s.db.QueryRow(ctx, `INSERT INTO links (code, target_url, fallback_url, rules, safety_status, safety_reason, safety_warnings, expires_at)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, NULLIF($6,''), $7, $8) RETURNING `+linkColumns,
		l.Code, l.TargetURL, l.FallbackURL, rulesJSON, l.SafetyStatus, l.SafetyReason, warningsJSON, l.ExpiresAt)
	created, err := scanLink(row)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrCodeTaken
	}
	if err != nil {
		return err
	}
	*l = *created
	return nil
}

func (s *Store) GetByCode(ctx context.Context, code string) (*Link, error) {
	return scanLink(s.db.QueryRow(ctx, `SELECT `+linkColumns+` FROM links WHERE code=$1`, code))
}

func (s *Store) Delete(ctx context.Context, code string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM links WHERE code=$1`, code)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) List(ctx context.Context, limit, offset int) ([]*Link, error) {
	rows, err := s.db.Query(ctx, `SELECT `+linkColumns+` FROM links ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// DueForCheck returns active links not checked since `before`, oldest first.
func (s *Store) DueForCheck(ctx context.Context, before time.Time, limit int) ([]*Link, error) {
	rows, err := s.db.Query(ctx, `SELECT `+linkColumns+` FROM links
		WHERE NOT disabled AND (expires_at IS NULL OR expires_at > now())
		  AND (last_checked_at IS NULL OR last_checked_at < $1)
		ORDER BY last_checked_at NULLS FIRST LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) UpdateHealth(ctx context.Context, id int64, status string, statusCode, failures int, at time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE links SET health_status=$2, last_status_code=NULLIF($3,0), consecutive_failures=$4, last_checked_at=$5 WHERE id=$1`,
		id, status, statusCode, failures, at)
	return err
}

func (s *Store) UpdateSafety(ctx context.Context, id int64, status, reason string, warnings []string) error {
	if warnings == nil {
		warnings = []string{}
	}
	w, _ := json.Marshal(warnings)
	_, err := s.db.Exec(ctx, `UPDATE links SET safety_status=$2, safety_reason=NULLIF($3,''), safety_warnings=$4 WHERE id=$1`, id, status, reason, w)
	return err
}

func (s *Store) InsertClicks(ctx context.Context, clicks []Click) error {
	rows := make([][]any, len(clicks))
	for i, c := range clicks {
		rows[i] = []any{c.LinkID, c.At, c.Device, nullable(c.Country), nullable(c.ReferrerHost), c.TargetURL, c.Reason}
	}
	_, err := s.db.CopyFrom(ctx, pgx.Identifier{"clicks"},
		[]string{"link_id", "clicked_at", "device", "country", "referrer_host", "target_url", "reason"}, pgx.CopyFromRows(rows))
	return err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type Count struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type Stats struct {
	Total     int64   `json:"total"`
	ByDevice  []Count `json:"by_device"`
	ByCountry []Count `json:"by_country"`
	ByTarget  []Count `json:"by_target"`
	ByReason  []Count `json:"by_reason"`
	ByDay     []Count `json:"by_day"`
}

func (s *Store) Stats(ctx context.Context, linkID int64, since time.Time) (*Stats, error) {
	st := &Stats{}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM clicks WHERE link_id=$1 AND clicked_at >= $2`, linkID, since).Scan(&st.Total); err != nil {
		return nil, err
	}
	groups := []struct {
		expr string
		dst  *[]Count
	}{
		{"device", &st.ByDevice},
		{"COALESCE(country,'??')", &st.ByCountry},
		{"target_url", &st.ByTarget},
		{"reason", &st.ByReason},
		{"to_char(date_trunc('day', clicked_at), 'YYYY-MM-DD')", &st.ByDay},
	}
	for _, g := range groups {
		order := "2 DESC"
		if g.dst == &st.ByDay {
			order = "1"
		}
		rows, err := s.db.Query(ctx, fmt.Sprintf(`SELECT %s AS k, count(*) FROM clicks WHERE link_id=$1 AND clicked_at >= $2 GROUP BY k ORDER BY %s LIMIT 100`, g.expr, order), linkID, since)
		if err != nil {
			return nil, err
		}
		counts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Count, error) {
			var c Count
			return c, r.Scan(&c.Key, &c.Count)
		})
		if err != nil {
			return nil, err
		}
		if counts == nil {
			counts = []Count{}
		}
		*g.dst = counts
	}
	return st, nil
}
