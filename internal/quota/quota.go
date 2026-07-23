// Package quota measures Maildir disk usage and answers "does another
// message still fit?" against per-mailbox and per-domain limits.
//
// Usage is the sum of the file sizes under a mailbox root (every folder's
// cur/new/tmp). Because walking a large mailbox on every delivery would
// be costly, a Manager caches each mailbox's usage for a short TTL and
// bumps it in memory as messages are delivered; the walk re-runs when the
// entry expires, so an expunge is reflected within one TTL. The cache is
// only an accelerator — a cold or expired entry always re-measures the
// disk.
package quota

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ParseSize turns a human size ("2G", "500M", "1048576", "10 GB") into
// bytes. Units are binary (1K = 1024). Empty means 0 (no limit).
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s[:i]), 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))
	unit = strings.TrimSuffix(strings.TrimSuffix(unit, "IB"), "B")
	var mult int64
	switch unit {
	case "":
		mult = 1
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	case "T":
		mult = 1 << 40
	default:
		return 0, fmt.Errorf("invalid size unit in %q", s)
	}
	return int64(n * float64(mult)), nil
}

// Usage sums the size of every file under a Maildir root (all folders,
// cur/new/tmp). A missing directory is zero, not an error.
func Usage(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep counting
		}
		if d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	return total, err
}

// Manager caches mailbox usage.
type Manager struct {
	mu    sync.Mutex
	ttl   time.Duration
	cache map[string]entry
	now   func() time.Time
	usage func(string) (int64, error) // injectable for tests
}

type entry struct {
	bytes int64
	at    time.Time
}

// New returns a Manager caching usage for ttl.
func New(ttl time.Duration) *Manager {
	return &Manager{
		ttl:   ttl,
		cache: map[string]entry{},
		now:   time.Now,
		usage: Usage,
	}
}

// Get returns a mailbox's usage, re-measuring the disk when the cached
// value is missing or older than the TTL.
func (m *Manager) Get(dir string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if e, ok := m.cache[dir]; ok && now.Sub(e.at) < m.ttl {
		return e.bytes
	}
	b, err := m.usage(dir)
	if err != nil {
		// On a measurement error keep any previous value rather than
		// pretending the mailbox is empty (which would defeat the quota).
		if e, ok := m.cache[dir]; ok {
			return e.bytes
		}
		return 0
	}
	m.cache[dir] = entry{bytes: b, at: now}
	return b
}

// Add bumps a mailbox's cached usage after a delivery, so the next check
// sees the new size without re-walking. A no-op when the entry is cold
// (the next Get measures the disk, which already includes the message).
func (m *Manager) Add(dir string, delta int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.cache[dir]; ok {
		e.bytes += delta
		m.cache[dir] = e
	}
}
