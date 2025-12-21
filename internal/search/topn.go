package search

import (
	"net/netip"
	"sort"
	"sync"
)

type topN struct {
	n   int
	mu  sync.Mutex
	buf []TopResult
}

func newTopN(n int) *topN {
	return &topN{n: n, buf: make([]TopResult, 0, n)}
}

func (t *topN) Consider(r TopResult) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.n <= 0 {
		return
	}

	// Dedup by IP: keep best score for same IP.
	for i := range t.buf {
		if t.buf[i].IP == r.IP {
			if r.ScoreMS < t.buf[i].ScoreMS {
				t.buf[i] = r
			}
			t.sortLocked()
			t.trimLocked()
			return
		}
	}

	t.buf = append(t.buf, r)
	t.sortLocked()
	t.trimLocked()
}

func (t *topN) Best() TopResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.buf) == 0 {
		return TopResult{IP: netip.Addr{}}
	}
	return t.buf[0]
}

func (t *topN) Snapshot() []TopResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TopResult, len(t.buf))
	copy(out, t.buf)
	return out
}

func (t *topN) sortLocked() {
	sort.SliceStable(t.buf, func(i, j int) bool {
		return t.buf[i].ScoreMS < t.buf[j].ScoreMS
	})
}

func (t *topN) trimLocked() {
	if len(t.buf) > t.n {
		t.buf = t.buf[:t.n]
	}
}
