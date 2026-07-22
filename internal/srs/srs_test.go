package srs

import (
	"testing"
	"time"
)

const secret = "a-long-random-server-secret"

func TestForwardReverseRoundTrip(t *testing.T) {
	orig := "news@brand.com"
	fwd := Forward(secret, "example.com", orig)

	if !IsSRS(localOf(fwd)) {
		t.Fatalf("forwarded address is not SRS: %q", fwd)
	}
	if got := domainOf(fwd); got != "example.com" {
		t.Errorf("forward domain = %q, want example.com", got)
	}
	back, ok := Reverse(secret, fwd)
	if !ok || back != orig {
		t.Errorf("reverse = %q, %v; want %q, true", back, ok, orig)
	}
}

func TestReverseRejectsTampering(t *testing.T) {
	fwd := Forward(secret, "example.com", "news@brand.com")
	// Flip the encoded original domain: the HMAC must no longer verify,
	// which is what stops verta becoming an open backscatter relay.
	tampered := replace(fwd, "brand.com", "evil.com")
	if _, ok := Reverse(secret, tampered); ok {
		t.Error("a tampered SRS address must not reverse")
	}
	// A different secret must not verify our address either.
	if _, ok := Reverse("other-secret", fwd); ok {
		t.Error("wrong secret must not reverse")
	}
}

func TestReverseRejectsStale(t *testing.T) {
	// Forge an address timestamped well outside the window by rewriting
	// with a clock far in the past, then reversing at "now".
	old := forwardAt(secret, "example.com", "news@brand.com", time.Now().AddDate(0, 0, -40))
	if _, ok := Reverse(secret, old); ok {
		t.Error("a stale SRS address must not reverse")
	}
}

func TestEmptySenderStaysNull(t *testing.T) {
	if got := Forward(secret, "example.com", ""); got != "" {
		t.Errorf("null return-path must stay empty, got %q", got)
	}
}

func TestNonSRSNotReversed(t *testing.T) {
	if _, ok := Reverse(secret, "plain@example.com"); ok {
		t.Error("a plain address is not reversible")
	}
}

// --- helpers ---

// forwardAt is Forward with an injectable clock, for the staleness test.
func forwardAt(secret, dom, sender string, at time.Time) string {
	tt := timestamp(at)
	l, d, _ := split(sender)
	h := sign(secret, tt, d, l)
	return "SRS0=" + h + "=" + tt + "=" + d + "=" + l + "@" + dom
}

func localOf(a string) string  { l, _, _ := split(a); return l }
func domainOf(a string) string { _, d, _ := split(a); return d }

func replace(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
