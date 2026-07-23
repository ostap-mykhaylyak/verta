package quota

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"":       0,
		"0":      0,
		"1024":   1024,
		"1K":     1 << 10,
		"500M":   500 << 20,
		"2G":     2 << 30,
		"1T":     1 << 40,
		"10MB":   10 << 20,
		"1GiB":   1 << 30,
		"1.5G":   1<<30 + 1<<29,
		" 100 M": 100 << 20,
	}
	for in, want := range cases {
		got, err := ParseSize(in)
		if err != nil {
			t.Errorf("ParseSize(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseSize(%q) = %d, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"abc", "1X", "-5M", "M"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) should error", bad)
		}
	}
}

// writeMsg drops a file of n bytes into a maildir folder.
func writeMsg(t *testing.T, dir, sub string, n int) {
	t.Helper()
	d := filepath.Join(dir, sub)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, randName(t)), make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
}

var nameSeq int

func randName(t *testing.T) string {
	nameSeq++
	return t.Name() + "-" + time.Now().Format("150405.000000000") + "-" + itoa(nameSeq)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestUsageSumsAllFolders(t *testing.T) {
	root := t.TempDir()
	writeMsg(t, root, "new", 1000)
	writeMsg(t, root, "cur", 2000)
	writeMsg(t, root, ".Sent/cur", 500) // a subfolder counts too
	got, err := Usage(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3500 {
		t.Errorf("usage = %d, want 3500", got)
	}
}

func TestUsageMissingIsZero(t *testing.T) {
	got, err := Usage(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil || got != 0 {
		t.Errorf("missing dir = %d, %v; want 0, nil", got, err)
	}
}

// The Manager caches usage for the TTL and honours Add between walks.
func TestManagerCacheAndAdd(t *testing.T) {
	var walks int
	m := New(time.Minute)
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	m.usage = func(string) (int64, error) { walks++; return 1000, nil }

	if m.Get("/mbox") != 1000 || walks != 1 {
		t.Fatalf("first Get should walk once: walks=%d", walks)
	}
	if m.Get("/mbox") != 1000 || walks != 1 {
		t.Errorf("second Get within TTL must use the cache: walks=%d", walks)
	}
	// A delivery bumps the cached value without a walk.
	m.Add("/mbox", 250)
	if m.Get("/mbox") != 1250 || walks != 1 {
		t.Errorf("Add should bump the cache: got=%d walks=%d", m.Get("/mbox"), walks)
	}
	// After the TTL the disk is re-measured.
	now = now.Add(2 * time.Minute)
	if m.Get("/mbox") != 1000 || walks != 2 {
		t.Errorf("expired entry should re-walk: got=%d walks=%d", m.Get("/mbox"), walks)
	}
}
