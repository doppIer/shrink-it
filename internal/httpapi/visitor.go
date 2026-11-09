package httpapi

import (
	"hash/fnv"
	"net/http"
	"strings"

	"github.com/doppIer/shrink-it/internal/device"
	"github.com/doppIer/shrink-it/internal/rules"
)

// countryHeaders are set by common edge proxies / CDNs. Put Cloudflare or a
// GeoIP-enabled reverse proxy in front of shrink-it to get country routing.
var countryHeaders = []string{"CF-IPCountry", "X-Country-Code", "X-Geo-Country", "CloudFront-Viewer-Country"}

func (s *Server) visitor(r *http.Request, code string) rules.Visitor {
	ua := r.UserAgent()
	ip := s.clientIP(r)
	h := fnv.New32a()
	h.Write([]byte(ip + "|" + ua + "|" + code))
	return rules.Visitor{
		Device:   device.Detect(ua),
		Country:  country(r),
		Language: primaryLanguage(r.Header.Get("Accept-Language")),
		Now:      s.Now(),
		Bucket:   h.Sum32(),
	}
}

func country(r *http.Request) string {
	for _, h := range countryHeaders {
		if v := strings.ToUpper(strings.TrimSpace(r.Header.Get(h))); len(v) == 2 && v != "XX" {
			return v
		}
	}
	return ""
}

// primaryLanguage returns the 2-letter code of the first Accept-Language tag.
func primaryLanguage(h string) string {
	tag := strings.TrimSpace(strings.SplitN(strings.SplitN(h, ",", 2)[0], ";", 2)[0])
	if i := strings.IndexByte(tag, '-'); i >= 0 {
		tag = tag[:i]
	}
	tag = strings.ToLower(tag)
	if len(tag) != 2 {
		return ""
	}
	return tag
}
