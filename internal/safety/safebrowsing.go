package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SafeBrowsing checks URLs against the Google Safe Browsing v4 Lookup API.
// It is enabled only when SAFE_BROWSING_API_KEY is set.
type SafeBrowsing struct {
	APIKey   string
	Client   *http.Client
	Endpoint string // overridable for tests
}

func (*SafeBrowsing) Name() string { return "safe-browsing" }

func (s *SafeBrowsing) Check(ctx context.Context, u *url.URL) (Verdict, error) {
	endpoint := s.Endpoint
	if endpoint == "" {
		endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
	}
	body, _ := json.Marshal(map[string]any{
		"client": map[string]string{"clientId": "shrink-it", "clientVersion": "0.1.0"},
		"threatInfo": map[string]any{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []map[string]string{{"url": u.String()}},
		},
	})
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"?key="+url.QueryEscape(s.APIKey), bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("safe browsing: status %d", resp.StatusCode)
	}
	var out struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Verdict{}, err
	}
	if len(out.Matches) > 0 {
		return Verdict{Safe: false, Reason: "flagged by Google Safe Browsing: " + out.Matches[0].ThreatType}, nil
	}
	return Verdict{Safe: true}, nil
}
