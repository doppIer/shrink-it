package safety

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *urlT {
	t.Helper()
	u, err := ParseTarget(raw)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", raw, err)
	}
	return u
}

func TestParseTarget(t *testing.T) {
	bad := []string{"", "ftp://x.com", "javascript:alert(1)", "https://", "https://user:pw@x.com", "x.com", "https://" + strings.Repeat("a", 3000) + ".com"}
	for _, raw := range bad {
		if _, err := ParseTarget(raw); err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
	mustParse(t, "https://example.com/path?q=1")
}

func fakeLookup(m map[string][]string) LookupFunc {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		ips, ok := m[host]
		if !ok {
			return nil, errors.New("nxdomain")
		}
		var out []netip.Addr
		for _, s := range ips {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

func TestNetworkPolicy(t *testing.T) {
	p := NetworkPolicy{Lookup: fakeLookup(map[string][]string{
		"public.example":   {"93.184.216.34"},
		"internal.example": {"10.0.0.5"},
		"rebind.example":   {"93.184.216.34", "127.0.0.1"},
	})}
	cases := map[string]bool{
		"https://public.example":   true,
		"https://internal.example": false,
		"https://rebind.example":   false,
		"http://localhost:8080":    false,
		"http://127.0.0.1":         false,
		"http://[::1]/":            false,
		"http://169.254.169.254/":  false,
		"http://192.168.1.1/":      false,
		"https://8.8.8.8/":         true,
		"https://unknown.example/": true, // doesn't resolve -> warning only
	}
	for raw, want := range cases {
		v, err := p.Check(context.Background(), mustParse(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		if v.Safe != want {
			t.Errorf("%s: safe=%v want %v (%s)", raw, v.Safe, want, v.Reason)
		}
	}
}

func TestBlocklist(t *testing.T) {
	b := NewBlocklist()
	if err := b.Read(strings.NewReader("# comment\nevil.com\n0.0.0.0 phish.net # hosts style\n\n")); err != nil {
		t.Fatal(err)
	}
	if b.Len() != 2 {
		t.Fatalf("len=%d", b.Len())
	}
	cases := map[string]bool{
		"https://evil.com":          false,
		"https://login.evil.com/x":  false,
		"https://phish.net":         false,
		"https://notevil.com":       true,
		"https://evil.com.good.org": true,
	}
	for raw, want := range cases {
		v, _ := b.Check(context.Background(), mustParse(t, raw))
		if v.Safe != want {
			t.Errorf("%s: safe=%v want %v", raw, v.Safe, want)
		}
	}
}

func TestHeuristics(t *testing.T) {
	v, _ := Heuristics{}.Check(context.Background(), mustParse(t, "http://xn--pple-43d.com:8443/login"))
	if !v.Safe || len(v.Warnings) != 3 {
		t.Fatalf("got %+v", v)
	}
	v, _ = Heuristics{}.Check(context.Background(), mustParse(t, "https://github.com"))
	if len(v.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v", v.Warnings)
	}
}

type errChecker struct{}

func (errChecker) Name() string { return "flaky" }
func (errChecker) Check(context.Context, *urlT) (Verdict, error) {
	return Verdict{}, errors.New("timeout")
}

func TestScannerChain(t *testing.T) {
	s := Scanner{Checkers: []Checker{errChecker{}, Heuristics{}, NewBlocklist("evil.com")}}
	v := s.Scan(context.Background(), mustParse(t, "http://evil.com"))
	if v.Safe || v.Source != "blocklist" {
		t.Fatalf("expected blocklist block, got %+v", v)
	}
	if len(v.Warnings) < 2 {
		t.Fatalf("expected merged warnings, got %v", v.Warnings)
	}
}

func TestSafeBrowsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "k" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var buf [4096]byte
		n, _ := r.Body.Read(buf[:])
		if strings.Contains(string(buf[:n]), "malware.test") {
			w.Write([]byte(`{"matches":[{"threatType":"MALWARE"}]}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	sb := &SafeBrowsing{APIKey: "k", Endpoint: srv.URL}
	v, err := sb.Check(context.Background(), mustParse(t, "https://malware.test/x"))
	if err != nil || v.Safe {
		t.Fatalf("expected block: %+v %v", v, err)
	}
	v, err = sb.Check(context.Background(), mustParse(t, "https://fine.test"))
	if err != nil || !v.Safe {
		t.Fatalf("expected safe: %+v %v", v, err)
	}
}
