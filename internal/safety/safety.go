// Package safety validates target URLs and scans them for known threats.
//
// A Scanner runs a chain of Checkers. A checker can block a URL (Verdict.Safe
// = false) or attach soft warnings that are shown on the preview page.
package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

const maxURLLength = 2048

type Verdict struct {
	Safe     bool     `json:"safe"`
	Reason   string   `json:"reason,omitempty"`
	Source   string   `json:"source,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type Checker interface {
	Name() string
	Check(ctx context.Context, u *url.URL) (Verdict, error)
}

type Scanner struct {
	Checkers []Checker
}

// Scan runs every checker; the first blocking verdict wins, warnings are merged.
// Checker errors (e.g. an API timeout) are turned into warnings so one flaky
// provider never blocks link creation.
func (s Scanner) Scan(ctx context.Context, u *url.URL) Verdict {
	out := Verdict{Safe: true}
	for _, c := range s.Checkers {
		v, err := c.Check(ctx, u)
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s check unavailable", c.Name()))
			continue
		}
		out.Warnings = append(out.Warnings, v.Warnings...)
		if !v.Safe {
			out.Safe, out.Reason, out.Source = false, v.Reason, c.Name()
			return out
		}
	}
	return out
}

// ParseTarget validates the shape of a destination URL.
func ParseTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("url is required")
	}
	if len(raw) > maxURLLength {
		return nil, errors.New("url is too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("url is not valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("only http and https urls are allowed")
	}
	if u.Hostname() == "" {
		return nil, errors.New("url must have a host")
	}
	if u.User != nil {
		return nil, errors.New("urls with credentials are not allowed")
	}
	return u, nil
}

// LookupFunc resolves a host to IPs; injectable for tests.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func DefaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// NetworkPolicy blocks targets pointing at loopback/private/link-local
// addresses. This stops the shortener (and its health worker) being used for
// SSRF against your own network.
type NetworkPolicy struct {
	AllowPrivate bool
	Lookup       LookupFunc
}

func (NetworkPolicy) Name() string { return "network-policy" }

func (p NetworkPolicy) Check(ctx context.Context, u *url.URL) (Verdict, error) {
	if p.AllowPrivate {
		return Verdict{Safe: true}, nil
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return Verdict{Safe: false, Reason: "target points to localhost"}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !IsPublic(ip) {
			return Verdict{Safe: false, Reason: "target is a private address"}, nil
		}
		return Verdict{Safe: true}, nil
	}
	lookup := p.Lookup
	if lookup == nil {
		lookup = DefaultLookup
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return Verdict{Safe: true, Warnings: []string{"domain does not resolve right now"}}, nil
	}
	for _, ip := range ips {
		if !IsPublic(ip) {
			return Verdict{Safe: false, Reason: "domain resolves to a private address"}, nil
		}
	}
	return Verdict{Safe: true}, nil
}

// IsPublic reports whether ip is a globally routable unicast address.
func IsPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// Heuristics adds non-blocking warnings for patterns common in phishing.
type Heuristics struct{}

func (Heuristics) Name() string { return "heuristics" }

var shorteners = map[string]bool{"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true, "is.gd": true, "ow.ly": true, "cutt.ly": true}

func (Heuristics) Check(_ context.Context, u *url.URL) (Verdict, error) {
	var w []string
	host := strings.ToLower(u.Hostname())
	if _, err := netip.ParseAddr(host); err == nil {
		w = append(w, "target uses a raw IP address instead of a domain")
	}
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "xn--") {
			w = append(w, "domain uses internationalized characters (possible look-alike domain)")
			break
		}
	}
	if strings.Count(host, ".") >= 4 {
		w = append(w, "domain has an unusually deep subdomain chain")
	}
	if shorteners[host] {
		w = append(w, "target is another URL shortener (hides the final destination)")
	}
	if u.Scheme == "http" {
		w = append(w, "target does not use HTTPS")
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		w = append(w, "target uses a non-standard port")
	}
	return Verdict{Safe: true, Warnings: w}, nil
}
