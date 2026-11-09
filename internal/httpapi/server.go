// Package httpapi exposes the REST API, the redirect endpoint and the
// link preview / warning pages.
package httpapi

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/doppIer/shrink-it/internal/rules"
	"github.com/doppIer/shrink-it/internal/safety"
	"github.com/doppIer/shrink-it/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

var tmpl = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

type Store interface {
	Create(ctx context.Context, l *store.Link) error
	GetByCode(ctx context.Context, code string) (*store.Link, error)
	Delete(ctx context.Context, code string) error
	List(ctx context.Context, limit, offset int) ([]*store.Link, error)
	Stats(ctx context.Context, linkID int64, since time.Time) (*store.Stats, error)
	Ping(ctx context.Context) error
}

type Cache interface {
	GetLink(ctx context.Context, code string) (*store.Link, bool)
	Set(ctx context.Context, l *store.Link)
	Delete(ctx context.Context, code string)
	Allow(ctx context.Context, bucket string, limit int, window time.Duration) (bool, error)
	Ping(ctx context.Context) error
}

type Recorder interface {
	Record(c store.Click)
}

type Server struct {
	Store           Store
	Cache           Cache
	Scanner         safety.Scanner
	Recorder        Recorder
	Log             *slog.Logger
	BaseURL         string
	AdminToken      string
	TrustProxy      bool
	CreateRateLimit int
	Now             func() time.Time
}

func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/links", s.auth(s.handleCreate))
	mux.HandleFunc("GET /api/links", s.auth(s.handleList))
	mux.HandleFunc("GET /api/links/{code}", s.auth(s.handleGet))
	mux.HandleFunc("DELETE /api/links/{code}", s.auth(s.handleDelete))
	mux.HandleFunc("GET /api/links/{code}/stats", s.auth(s.handleStats))
	mux.HandleFunc("POST /api/scan", s.auth(s.handleScan))
	mux.HandleFunc("GET /{code}", s.handleRedirect)
	mux.HandleFunc("GET /{code}/preview", s.handlePreview)
	return s.logRequests(mux)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AdminToken == "" {
			next(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.AdminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid token")
			return
		}
		next(w, r)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		s.Log.Debug("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "dur", time.Since(start))
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.ExecuteTemplate(w, "index.html", map[string]any{"BaseURL": s.BaseURL, "AuthRequired": s.AdminToken != ""})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	res := map[string]string{"postgres": "ok", "redis": "ok"}
	code := http.StatusOK
	if err := s.Store.Ping(ctx); err != nil {
		res["postgres"], code = err.Error(), http.StatusServiceUnavailable
	}
	if err := s.Cache.Ping(ctx); err != nil {
		res["redis"], code = err.Error(), http.StatusServiceUnavailable
	}
	writeJSON(w, code, res)
}

// lookup reads through Redis to Postgres.
func (s *Server) lookup(ctx context.Context, code string) (*store.Link, error) {
	if l, ok := s.Cache.GetLink(ctx, code); ok {
		return l, nil
	}
	l, err := s.Store.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	s.Cache.Set(ctx, l)
	return l, nil
}

func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	l, err := s.lookup(r.Context(), code)
	if err == store.ErrNotFound {
		s.renderPage(w, http.StatusNotFound, "notfound", nil)
		return
	}
	if err != nil {
		s.Log.Error("lookup", "code", code, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if l.Disabled || l.Expired(s.Now()) {
		s.renderPage(w, http.StatusGone, "gone", l)
		return
	}
	if l.SafetyStatus == "flagged" {
		// Never forward visitors to a flagged destination; show the warning page.
		s.renderPage(w, http.StatusForbidden, "blocked", l)
		return
	}

	v := s.visitor(r, code)
	var d rules.Decision
	if l.HealthStatus == "broken" && l.FallbackURL != "" {
		d = rules.Decision{Target: l.FallbackURL, Reason: "fallback"}
	} else {
		d = l.Rules.Resolve(v, l.TargetURL)
	}

	s.Recorder.Record(store.Click{
		LinkID: l.ID, At: v.Now, Device: v.Device, Country: v.Country,
		ReferrerHost: referrerHost(r.Referer()), TargetURL: d.Target, Reason: d.Reason,
	})
	// 302 + no-store: browsers must ask us every time, otherwise rules,
	// A/B tests and analytics stop working for repeat visitors.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("X-Shrinkit-Reason", d.Reason)
	http.Redirect(w, r, d.Target, http.StatusFound)
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	l, err := s.lookup(r.Context(), r.PathValue("code"))
	if err == store.ErrNotFound {
		s.renderPage(w, http.StatusNotFound, "notfound", nil)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := "preview"
	if l.SafetyStatus == "flagged" {
		state = "blocked"
	}
	s.renderPage(w, http.StatusOK, state, l)
}

func (s *Server) renderPage(w http.ResponseWriter, status int, state string, l *store.Link) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = tmpl.ExecuteTemplate(w, "preview.html", map[string]any{"State": state, "Link": l, "BaseURL": s.BaseURL})
}

type createRequest struct {
	URL         string     `json:"url"`
	Code        string     `json:"code,omitempty"`
	FallbackURL string     `json:"fallback_url,omitempty"`
	Rules       rules.Set  `json:"rules"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type linkResponse struct {
	*store.Link
	ShortURL   string `json:"short_url"`
	PreviewURL string `json:"preview_url"`
}

func (s *Server) respondLink(w http.ResponseWriter, status int, l *store.Link) {
	base := strings.TrimRight(s.BaseURL, "/")
	writeJSON(w, status, linkResponse{Link: l, ShortURL: base + "/" + l.Code, PreviewURL: base + "/" + l.Code + "/preview"})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	links, err := s.Store.List(r.Context(), 100, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list links")
		return
	}
	base := strings.TrimRight(s.BaseURL, "/")
	out := make([]linkResponse, 0, len(links))
	for _, l := range links {
		out = append(out, linkResponse{Link: l, ShortURL: base + "/" + l.Code, PreviewURL: base + "/" + l.Code + "/preview"})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	l, err := s.Store.GetByCode(r.Context(), r.PathValue("code"))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	s.respondLink(w, http.StatusOK, l)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if err := s.Store.Delete(r.Context(), code); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "link not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.Cache.Delete(r.Context(), code)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	l, err := s.Store.GetByCode(r.Context(), r.PathValue("code"))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	days := 30
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 && d <= 365 {
		days = d
	}
	st, err := s.Store.Stats(r.Context(), l.ID, s.Now().AddDate(0, 0, -days))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stats failed")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleScan lets clients check a URL without creating a link.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u, err := safety.ParseTarget(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Scanner.Scan(r.Context(), u))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return xr
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func referrerHost(ref string) string {
	if ref == "" {
		return ""
	}
	if u, err := url.Parse(ref); err == nil {
		return u.Hostname()
	}
	return ""
}
