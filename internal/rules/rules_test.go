package rules

import (
	"testing"
	"time"
)

func TestResolveRules(t *testing.T) {
	set := Set{Rules: []Rule{
		{Name: "app-store", When: Condition{Devices: []string{"ios"}}, Target: "https://apps.apple.com/x"},
		{Name: "play", When: Condition{Devices: []string{"android"}}, Target: "https://play.google.com/x"},
		{Name: "tr-night", When: Condition{Countries: []string{"TR"}, Hours: &HourRange{From: 22, To: 6, TZ: "Europe/Istanbul"}}, Target: "https://night.example"},
	}}
	noon := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)      // 12:00 Istanbul
	midnight := time.Date(2026, 1, 5, 21, 0, 0, 0, time.UTC) // 00:00 Istanbul

	cases := []struct {
		v      Visitor
		target string
		reason string
	}{
		{Visitor{Device: "ios", Now: noon}, "https://apps.apple.com/x", "rule:app-store"},
		{Visitor{Device: "android", Now: noon}, "https://play.google.com/x", "rule:play"},
		{Visitor{Device: "desktop", Country: "tr", Now: midnight}, "https://night.example", "rule:tr-night"},
		{Visitor{Device: "desktop", Country: "TR", Now: noon}, "https://default", "default"},
		{Visitor{Device: "desktop", Country: "DE", Now: midnight}, "https://default", "default"},
	}
	for i, c := range cases {
		d := set.Resolve(c.v, "https://default")
		if d.Target != c.target || d.Reason != c.reason {
			t.Errorf("case %d: got %+v want %s/%s", i, d, c.target, c.reason)
		}
	}
}

func TestResolveVariantsWeighted(t *testing.T) {
	set := Set{Variants: []Variant{{URL: "https://a", Weight: 70}, {URL: "https://b", Weight: 30}}}
	counts := map[string]int{}
	for b := uint32(0); b < 1000; b++ {
		counts[set.Resolve(Visitor{Bucket: b}, "https://default").Target]++
	}
	if counts["https://a"] != 700 || counts["https://b"] != 300 {
		t.Fatalf("unexpected split %v", counts)
	}
	// sticky: same bucket -> same target
	if set.Resolve(Visitor{Bucket: 42}, "").Target != set.Resolve(Visitor{Bucket: 42}, "").Target {
		t.Fatal("variant assignment not sticky")
	}
}

func TestWeekdays(t *testing.T) {
	set := Set{Rules: []Rule{{When: Condition{Weekdays: []int{0, 6}}, Target: "https://weekend"}}}
	sat := time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC)
	mon := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	if got := set.Resolve(Visitor{Now: sat}, "d").Target; got != "https://weekend" {
		t.Errorf("saturday: %s", got)
	}
	if got := set.Resolve(Visitor{Now: mon}, "d").Target; got != "d" {
		t.Errorf("monday: %s", got)
	}
}

func TestValidate(t *testing.T) {
	bad := []Set{
		{Rules: []Rule{{Target: ""}}},
		{Rules: []Rule{{Target: "x", When: Condition{Hours: &HourRange{From: 5, To: 5}}}}},
		{Rules: []Rule{{Target: "x", When: Condition{Hours: &HourRange{From: 1, To: 2, TZ: "Mars/Base"}}}}},
		{Rules: []Rule{{Target: "x", When: Condition{Weekdays: []int{7}}}}},
		{Variants: []Variant{{URL: "x", Weight: 0}}},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	ok := Set{Rules: []Rule{{Target: "x", When: Condition{Hours: &HourRange{From: 9, To: 17, TZ: "Europe/Istanbul"}}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}
