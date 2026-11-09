// Package rules implements smart redirect routing: per-visitor rules
// (device, country, language, time window) and weighted A/B variants.
package rules

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// HourRange is a local-time window [From, To). From > To wraps midnight
// (e.g. 22 -> 6 means "night").
type HourRange struct {
	From int    `json:"from"`
	To   int    `json:"to"`
	TZ   string `json:"tz,omitempty"`
}

// Condition fields are ANDed; values inside a list are ORed.
// Empty fields match everything.
type Condition struct {
	Devices   []string   `json:"devices,omitempty"`   // ios, android, desktop, bot
	Countries []string   `json:"countries,omitempty"` // ISO 3166-1 alpha-2
	Languages []string   `json:"languages,omitempty"` // ISO 639-1, e.g. "tr"
	Weekdays  []int      `json:"weekdays,omitempty"`  // 0 = Sunday
	Hours     *HourRange `json:"hours,omitempty"`
}

type Rule struct {
	Name   string    `json:"name,omitempty"`
	When   Condition `json:"when"`
	Target string    `json:"target"`
}

type Variant struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// Set is stored as JSON alongside each link.
type Set struct {
	Rules    []Rule    `json:"rules,omitempty"`
	Variants []Variant `json:"variants,omitempty"`
}

// Visitor describes the incoming request.
type Visitor struct {
	Device   string
	Country  string
	Language string
	Now      time.Time
	// Bucket is a stable per-visitor hash so A/B assignment is sticky.
	Bucket uint32
}

// Decision is the routing result and why it was chosen (for analytics).
type Decision struct {
	Target string
	Reason string
}

// Resolve picks a target: first matching rule wins, then A/B variants,
// then the link's default target.
func (s Set) Resolve(v Visitor, def string) Decision {
	for i, r := range s.Rules {
		if r.When.matches(v) {
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("rule-%d", i+1)
			}
			return Decision{Target: r.Target, Reason: "rule:" + name}
		}
	}
	total := 0
	for _, va := range s.Variants {
		total += va.Weight
	}
	if total > 0 {
		pick := int(v.Bucket % uint32(total))
		for i, va := range s.Variants {
			if pick < va.Weight {
				return Decision{Target: va.URL, Reason: fmt.Sprintf("variant:%d", i+1)}
			}
			pick -= va.Weight
		}
	}
	return Decision{Target: def, Reason: "default"}
}

// URLs returns every target URL referenced by the set (for validation/scanning).
func (s Set) URLs() []string {
	var out []string
	for _, r := range s.Rules {
		out = append(out, r.Target)
	}
	for _, v := range s.Variants {
		out = append(out, v.URL)
	}
	return out
}

func (s Set) Validate() error {
	if len(s.Rules) > 50 || len(s.Variants) > 20 {
		return errors.New("too many rules or variants")
	}
	for i, r := range s.Rules {
		if r.Target == "" {
			return fmt.Errorf("rule %d: target is required", i+1)
		}
		if h := r.When.Hours; h != nil {
			if h.From < 0 || h.From > 23 || h.To < 0 || h.To > 24 || h.From == h.To {
				return fmt.Errorf("rule %d: invalid hours %d-%d", i+1, h.From, h.To)
			}
			if h.TZ != "" {
				if _, err := time.LoadLocation(h.TZ); err != nil {
					return fmt.Errorf("rule %d: unknown timezone %q", i+1, h.TZ)
				}
			}
		}
		for _, d := range r.When.Weekdays {
			if d < 0 || d > 6 {
				return fmt.Errorf("rule %d: weekday must be 0-6", i+1)
			}
		}
	}
	for i, v := range s.Variants {
		if v.URL == "" || v.Weight <= 0 {
			return fmt.Errorf("variant %d: url and positive weight required", i+1)
		}
	}
	return nil
}

func (c Condition) matches(v Visitor) bool {
	if len(c.Devices) > 0 && !containsFold(c.Devices, v.Device) {
		return false
	}
	if len(c.Countries) > 0 && !containsFold(c.Countries, v.Country) {
		return false
	}
	if len(c.Languages) > 0 && !containsFold(c.Languages, v.Language) {
		return false
	}
	if len(c.Weekdays) == 0 && c.Hours == nil {
		return true
	}
	now := v.Now
	if c.Hours != nil && c.Hours.TZ != "" {
		if loc, err := time.LoadLocation(c.Hours.TZ); err == nil {
			now = now.In(loc)
		}
	}
	if len(c.Weekdays) > 0 {
		ok := false
		for _, d := range c.Weekdays {
			if int(now.Weekday()) == d {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if h := c.Hours; h != nil {
		hr := now.Hour()
		if h.From < h.To {
			return hr >= h.From && hr < h.To
		}
		return hr >= h.From || hr < h.To
	}
	return true
}

func containsFold(list []string, s string) bool {
	if s == "" {
		return false
	}
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
