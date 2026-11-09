package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/doppIer/shrink-it/internal/safety"
	"github.com/doppIer/shrink-it/internal/shortcode"
	"github.com/doppIer/shrink-it/internal/store"
)

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if s.CreateRateLimit > 0 {
		if ok, _ := s.Cache.Allow(r.Context(), "create:"+s.clientIP(r), s.CreateRateLimit, time.Minute); !ok {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded, try again in a minute")
			return
		}
	}
	var req createRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if err := req.Rules.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Code != "" && !shortcode.Valid(req.Code) {
		writeError(w, http.StatusBadRequest, "code must be 3-32 chars of letters, digits, '-' or '_'")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(s.Now()) {
		writeError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}

	// Validate and scan every URL the link can send people to.
	all := append([]string{req.URL}, req.Rules.URLs()...)
	if req.FallbackURL != "" {
		all = append(all, req.FallbackURL)
	}
	var warnings []string
	for _, raw := range all {
		u, err := safety.ParseTarget(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, raw+": "+err.Error())
			return
		}
		v := s.Scanner.Scan(r.Context(), u)
		if !v.Safe {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "destination rejected by safety scan", "url": raw, "reason": v.Reason, "source": v.Source})
			return
		}
		warnings = appendUnique(warnings, v.Warnings...)
	}

	link := &store.Link{
		TargetURL: req.URL, FallbackURL: req.FallbackURL, Rules: req.Rules, ExpiresAt: req.ExpiresAt,
		SafetyStatus: "safe", SafetyWarnings: warnings,
	}
	if req.Code != "" {
		link.Code = req.Code
		if err := s.Store.Create(r.Context(), link); errors.Is(err, store.ErrCodeTaken) {
			writeError(w, http.StatusConflict, "code already taken")
			return
		} else if err != nil {
			s.Log.Error("create link", "err", err)
			writeError(w, http.StatusInternalServerError, "could not create link")
			return
		}
	} else {
		var err error
		for attempt := 0; attempt < 5; attempt++ {
			link.Code = shortcode.Generate(7)
			if err = s.Store.Create(r.Context(), link); !errors.Is(err, store.ErrCodeTaken) {
				break
			}
		}
		if err != nil {
			s.Log.Error("create link", "err", err)
			writeError(w, http.StatusInternalServerError, "could not create link")
			return
		}
	}
	s.respondLink(w, http.StatusCreated, link)
}

func appendUnique(dst []string, items ...string) []string {
	for _, it := range items {
		found := false
		for _, d := range dst {
			if d == it {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, it)
		}
	}
	return dst
}
