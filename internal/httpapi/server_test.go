package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/doppIer/shrink-it/internal/rules"
	"github.com/doppIer/shrink-it/internal/safety"
	"github.com/doppIer/shrink-it/internal/store"
)

type memStore struct {
	mu    sync.Mutex
	links map[string]*store.Link
	next  int64
}

func (m *memStore) Create(_ context.Context, l *store.Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.links[l.Code]; ok {
		return store.ErrCodeTaken
	}
	m.next++
	l.ID, l.HealthStatus, l.CreatedAt = m.next, "unknown", time.Now()
	cp := *l
	m.links[l.Code] = &cp
	return nil
}
func (m *memStore) GetByCode(_ context.Context, code string) (*store.Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.links[code]; ok {
		cp := *l
		return &cp, nil
	}
	return nil, store.ErrNotFound
}
func (m *memStore) Delete(_ context.Context, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.links[code]; !ok {
		return store.ErrNotFound
	}
	delete(m.links, code)
	return nil
}
func (m *memStore) List(context.Context, int, int) ([]*store.Link, error) { return nil, nil }
func (m *memStore) Stats(context.Context, int64, time.Time) (*store.Stats, error) {
	return &store.Stats{}, nil
}
func (m *memStore) Ping(context.Context) error { return nil }

type noCache struct{}

func (noCache) GetLink(context.Context, string) (*store.Link, bool) { return nil, false }
func (noCache) Set(context.Context, *store.Link)                    {}
func (noCache) Delete(context.Context, string)                      {}
func (noCache) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}
func (noCache) Ping(context.Context) error { return nil }

type memRecorder struct {
	mu     sync.Mutex
	clicks []store.Click
}

func (r *memRecorder) Record(c store.Click) {
	r.mu.Lock()
	r.clicks = append(r.clicks, c)
	r.mu.Unlock()
}

func newTestServer() (*Server, *memStore, *memRecorder) {
	st := &memStore{links: map[string]*store.Link{}}
	rec := &memRecorder{}
	s := &Server{
		Store: st, Cache: noCache{}, Recorder: rec, BaseURL: "http://sho.rt", AdminToken: "secret",
		Scanner: safety.Scanner{Checkers: []safety.Checker{safety.Heuristics{}, safety.NewBlocklist("evil.com")}},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return s, st, rec
}

func do(h http.Handler, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

var auth = map[string]string{"Authorization": "Bearer secret"}

func TestCreateRequiresToken(t *testing.T) {
	s, _, _ := newTestServer()
	if w := do(s.Handler(), "POST", "/api/links", `{"url":"https://example.com"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestCreateAndSmartRedirect(t *testing.T) {
	s, _, rec := newTestServer()
	h := s.Handler()
	body := `{"url":"https://example.com","code":"app","rules":{"rules":[{"name":"ios","when":{"devices":["ios"]},"target":"https://apps.apple.com/app"}]}}`
	if w := do(h, "POST", "/api/links", body, auth); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	w := do(h, "GET", "/app", "", map[string]string{"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"})
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://apps.apple.com/app" {
		t.Fatalf("ios redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = do(h, "GET", "/app", "", map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"})
	if w.Header().Get("Location") != "https://example.com" || w.Header().Get("X-Shrinkit-Reason") != "default" {
		t.Fatalf("desktop redirect: %s", w.Header().Get("Location"))
	}
	if len(rec.clicks) != 2 || rec.clicks[0].Reason != "rule:ios" {
		t.Fatalf("clicks: %+v", rec.clicks)
	}
	if w := do(h, "POST", "/api/links", body, auth); w.Code != http.StatusConflict {
		t.Fatalf("duplicate code: %d", w.Code)
	}
}

func TestCreateRejectsUnsafe(t *testing.T) {
	s, _, _ := newTestServer()
	h := s.Handler()
	cases := map[string]int{
		`{"url":"https://login.evil.com"}`: http.StatusUnprocessableEntity,
		`{"url":"https://ok.com","rules":{"variants":[{"url":"https://evil.com","weight":1}]}}`: http.StatusUnprocessableEntity,
		`{"url":"javascript:alert(1)"}`:                                http.StatusBadRequest,
		`{"url":"https://ok.com","code":"api"}`:                        http.StatusBadRequest,
		`{"url":"https://ok.com","unknown":true}`:                      http.StatusBadRequest,
		`{"url":"https://ok.com","expires_at":"2000-01-01T00:00:00Z"}`: http.StatusBadRequest,
	}
	for body, want := range cases {
		if w := do(h, "POST", "/api/links", body, auth); w.Code != want {
			t.Errorf("%s: got %d want %d (%s)", body, w.Code, want, w.Body)
		}
	}
}

func TestBrokenTargetUsesFallback(t *testing.T) {
	s, st, _ := newTestServer()
	st.Create(context.Background(), &store.Link{Code: "fb", TargetURL: "https://down.example", FallbackURL: "https://backup.example", SafetyStatus: "safe"})
	st.links["fb"].HealthStatus = "broken"
	w := do(s.Handler(), "GET", "/fb", "", nil)
	if w.Header().Get("Location") != "https://backup.example" || w.Header().Get("X-Shrinkit-Reason") != "fallback" {
		t.Fatalf("got %s / %s", w.Header().Get("Location"), w.Header().Get("X-Shrinkit-Reason"))
	}
}

func TestFlaggedLinkIsBlocked(t *testing.T) {
	s, st, rec := newTestServer()
	st.Create(context.Background(), &store.Link{Code: "bad", TargetURL: "https://was-fine.example", SafetyStatus: "flagged", SafetyReason: "phishing"})
	w := do(s.Handler(), "GET", "/bad", "", nil)
	if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "blocked") {
		t.Fatalf("expected warning page, got %d", w.Code)
	}
	if len(rec.clicks) != 0 {
		t.Fatal("blocked visit should not be recorded as a click")
	}
}

func TestExpiredAndMissing(t *testing.T) {
	s, st, _ := newTestServer()
	past := time.Now().Add(-time.Hour)
	st.Create(context.Background(), &store.Link{Code: "old", TargetURL: "https://x.example", SafetyStatus: "safe", ExpiresAt: &past})
	h := s.Handler()
	if w := do(h, "GET", "/old", "", nil); w.Code != http.StatusGone {
		t.Fatalf("expired: %d", w.Code)
	}
	if w := do(h, "GET", "/nope", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing: %d", w.Code)
	}
}

func TestPreviewShowsWarnings(t *testing.T) {
	s, st, _ := newTestServer()
	st.Create(context.Background(), &store.Link{Code: "pv", TargetURL: "http://example.com", SafetyStatus: "safe",
		SafetyWarnings: []string{"target does not use HTTPS"}, Rules: rules.Set{Variants: []rules.Variant{{URL: "https://a", Weight: 1}}}})
	w := do(s.Handler(), "GET", "/pv/preview", "", nil)
	b := w.Body.String()
	if w.Code != 200 || !strings.Contains(b, "does not use HTTPS") || !strings.Contains(b, "smart link") {
		t.Fatalf("preview: %d", w.Code)
	}
}

func TestVisitorParsing(t *testing.T) {
	cases := map[string]string{"tr-TR,tr;q=0.9,en;q=0.8": "tr", "en": "en", "*": "", "": "", "zh-Hant-TW": "zh"}
	for in, want := range cases {
		if got := primaryLanguage(in); got != want {
			t.Errorf("primaryLanguage(%q)=%q want %q", in, got, want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-IPCountry", "tr")
	if country(r) != "TR" {
		t.Fatal("country header not read")
	}
}

func TestFavicon(t *testing.T) {
	s, _, _ := newTestServer()
	w := do(s.Handler(), "GET", "/favicon.png", "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || w.Body.Len() < 100 {
		t.Fatalf("favicon: %d %s %d bytes", w.Code, w.Header().Get("Content-Type"), w.Body.Len())
	}
}
