// Package shortcode generates and validates short link codes.
package shortcode

import (
	"crypto/rand"
	"math/big"
	"regexp"
	"strings"
)

// alphabet skips look-alike characters (0/O, 1/l/I).
const alphabet = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

var (
	validRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)
	reserved = map[string]bool{"api": true, "healthz": true, "metrics": true, "static": true, "favicon.ico": true}
)

// Generate returns a random code of length n.
func Generate(n int) string {
	var b strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b.WriteByte(alphabet[x.Int64()])
	}
	return b.String()
}

// Valid reports whether a user-chosen code is acceptable.
func Valid(code string) bool {
	return validRe.MatchString(code) && !reserved[strings.ToLower(code)]
}
