package safety

import (
	"bufio"
	"context"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Blocklist blocks a domain and all of its subdomains. The file format is one
// domain per line; '#' comments and hosts-file lines ("0.0.0.0 evil.com") work,
// so public lists such as URLhaus or StevenBlack hosts can be dropped in.
type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]struct{}
}

func NewBlocklist(domains ...string) *Blocklist {
	b := &Blocklist{domains: map[string]struct{}{}}
	for _, d := range domains {
		b.add(d)
	}
	return b
}

func LoadBlocklist(path string) (*Blocklist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := NewBlocklist()
	return b, b.Read(f)
}

func (b *Blocklist) Read(r io.Reader) error {
	sc := bufio.NewScanner(r)
	b.mu.Lock()
	defer b.mu.Unlock()
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		b.addLocked(fields[len(fields)-1])
	}
	return sc.Err()
}

func (b *Blocklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.domains)
}

func (b *Blocklist) add(d string) {
	b.mu.Lock()
	b.addLocked(d)
	b.mu.Unlock()
}

func (b *Blocklist) addLocked(d string) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d != "" && d != "localhost" {
		b.domains[d] = struct{}{}
	}
}

func (*Blocklist) Name() string { return "blocklist" }

func (b *Blocklist) Check(_ context.Context, u *url.URL) (Verdict, error) {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	b.mu.RLock()
	defer b.mu.RUnlock()
	for h := host; h != ""; {
		if _, ok := b.domains[h]; ok {
			return Verdict{Safe: false, Reason: "domain is on the blocklist (" + h + ")"}, nil
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return Verdict{Safe: true}, nil
}
