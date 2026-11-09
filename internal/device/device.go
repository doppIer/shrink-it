// Package device does lightweight User-Agent classification.
package device

import "strings"

const (
	IOS     = "ios"
	Android = "android"
	Desktop = "desktop"
	Bot     = "bot"
)

var botMarkers = []string{"bot", "crawler", "spider", "slurp", "facebookexternalhit", "preview", "curl/", "wget/", "python-requests", "go-http-client"}

// Detect classifies a User-Agent string as ios, android, desktop or bot.
func Detect(ua string) string {
	l := strings.ToLower(ua)
	if l == "" {
		return Bot
	}
	for _, m := range botMarkers {
		if strings.Contains(l, m) {
			return Bot
		}
	}
	switch {
	case strings.Contains(l, "iphone"), strings.Contains(l, "ipad"), strings.Contains(l, "ipod"):
		return IOS
	case strings.Contains(l, "android"):
		return Android
	default:
		return Desktop
	}
}
