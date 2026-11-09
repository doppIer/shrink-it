package shortcode

import "testing"

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c := Generate(7)
		if len(c) != 7 || !Valid(c) {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
	}
	if len(seen) < 990 {
		t.Fatalf("too many collisions: %d unique", len(seen))
	}
}

func TestValid(t *testing.T) {
	cases := map[string]bool{"abc": true, "my-link_1": true, "ab": false, "api": false, "API": false, "has space": false, "ü-code": false}
	for in, want := range cases {
		if got := Valid(in); got != want {
			t.Errorf("Valid(%q)=%v want %v", in, got, want)
		}
	}
}
