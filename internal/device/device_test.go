package device

import "testing"

func TestDetect(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15":   IOS,
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120 Mobile": Android,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120":       Desktop,
		"Googlebot/2.1 (+http://www.google.com/bot.html)":                               Bot,
		"curl/8.4.0": Bot,
		"":           Bot,
	}
	for ua, want := range cases {
		if got := Detect(ua); got != want {
			t.Errorf("Detect(%q)=%s want %s", ua, got, want)
		}
	}
}
