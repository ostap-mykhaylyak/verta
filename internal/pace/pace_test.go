package pace

import (
	"testing"
	"time"
)

func withClock(c Config) (*Throttle, *time.Time) {
	t := New(c)
	now := time.Unix(1_000_000, 0)
	t.now = func() time.Time { return now }
	return t, &now
}

func rate1per(seconds float64) Limit { return Limit{Rate: 1 / seconds, Burst: 1} }

// Global: one message every five seconds toward gmail.
func TestGlobalOnePerFiveSeconds(t *testing.T) {
	th, clock := withClock(Config{Global: []Rule{{Match: "gmail.com", Limit: rate1per(5)}}})
	k := Key{Dest: "gmail.com"}

	if ok, _ := th.Reserve(k); !ok {
		t.Fatal("first should go")
	}
	ok, wait := th.Reserve(k)
	if ok || wait < 4*time.Second || wait > 5*time.Second {
		t.Fatalf("second should be held ~5s, got ok=%v wait=%v", ok, wait)
	}
	*clock = clock.Add(5 * time.Second)
	if ok, _ := th.Reserve(k); !ok {
		t.Error("allowed after 5s")
	}
}

// Per-mailbox beats per-domain beats global for the same destination.
func TestSenderScopePrecedence(t *testing.T) {
	th, _ := withClock(Config{
		Global:    []Rule{{Match: "*", Limit: rate1per(100)}}, // very slow default
		ByDomain:  map[string][]Rule{"a.com": {{Match: "*", Limit: rate1per(10)}}},
		ByMailbox: map[string][]Rule{"bulk@a.com": {{Match: "*", Limit: Limit{Rate: 1000, Burst: 1000}}}},
	})
	// The bulk mailbox uses its own generous bucket, not the domain's.
	for i := 0; i < 100; i++ {
		if ok, _ := th.Reserve(Key{Mailbox: "bulk@a.com", Domain: "a.com", Dest: "gmail.com"}); !ok {
			t.Fatalf("mailbox override should allow message %d", i+1)
		}
	}
	// Another mailbox in the same domain falls back to the domain bucket.
	if ok, _ := th.Reserve(Key{Mailbox: "joe@a.com", Domain: "a.com", Dest: "gmail.com"}); !ok {
		t.Fatal("domain first should pass")
	}
	if ok, _ := th.Reserve(Key{Mailbox: "joe@a.com", Domain: "a.com", Dest: "gmail.com"}); ok {
		t.Error("domain bucket (1/10s) should hold the second")
	}
	// A domain with no rule uses the global default.
	if ok, _ := th.Reserve(Key{Domain: "other.com", Dest: "gmail.com"}); !ok {
		t.Fatal("global first should pass")
	}
	if ok, _ := th.Reserve(Key{Domain: "other.com", Dest: "gmail.com"}); ok {
		t.Error("global default should hold the second")
	}
}

// Per-IP throttle is independent and applies on top of the sender scope.
func TestPerIPIndependent(t *testing.T) {
	th, _ := withClock(Config{
		PerIP: []Rule{{Match: "gmail.com", Limit: rate1per(5)}},
	})
	// IP .10 and IP .11 each get their own 1/5s bucket.
	if ok, _ := th.Reserve(Key{EgressIP: "203.0.113.10", Dest: "gmail.com"}); !ok {
		t.Fatal("IP .10 first should pass")
	}
	if ok, _ := th.Reserve(Key{EgressIP: "203.0.113.11", Dest: "gmail.com"}); !ok {
		t.Error("IP .11 must not be throttled by IP .10's bucket")
	}
	if ok, _ := th.Reserve(Key{EgressIP: "203.0.113.10", Dest: "gmail.com"}); ok {
		t.Error("IP .10 second should be held")
	}
}

// A delivery must satisfy BOTH the sender scope and the per-IP scope.
func TestSenderAndIPBothApply(t *testing.T) {
	th, clock := withClock(Config{
		ByDomain: map[string][]Rule{"a.com": {{Match: "gmail.com", Limit: Limit{Rate: 1000, Burst: 1000}}}}, // sender: free
		PerIP:    []Rule{{Match: "gmail.com", Limit: rate1per(5)}},                                          // ip: 1/5s
	})
	k := Key{Domain: "a.com", EgressIP: "203.0.113.10", Dest: "gmail.com"}
	if ok, _ := th.Reserve(k); !ok {
		t.Fatal("first should pass")
	}
	// Sender is free but the IP bucket is spent → held.
	if ok, wait := th.Reserve(k); ok || wait <= 0 {
		t.Errorf("per-IP limit must hold it even when the sender is free: ok=%v wait=%v", ok, wait)
	}
	*clock = clock.Add(5 * time.Second)
	if ok, _ := th.Reserve(k); !ok {
		t.Error("allowed once the IP token refills")
	}
}

func TestNilAndEmpty(t *testing.T) {
	var th *Throttle
	if ok, _ := th.Reserve(Key{Dest: "gmail.com"}); !ok {
		t.Error("nil throttle allows everything")
	}
	if New(Config{}) != nil {
		t.Error("empty config yields a nil throttle")
	}
	// A configured throttle with no rule for this delivery allows it.
	th2 := New(Config{Global: []Rule{{Match: "gmail.com", Limit: rate1per(5)}}})
	for i := 0; i < 50; i++ {
		if ok, _ := th2.Reserve(Key{Dest: "outlook.com"}); !ok {
			t.Fatal("a destination with no rule is unthrottled")
		}
	}
}
