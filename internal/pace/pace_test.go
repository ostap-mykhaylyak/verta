package pace

import (
	"testing"
	"time"
)

// withClock returns a Throttle whose clock the test drives.
func withClock(rules []Rule) (*Throttle, *time.Time) {
	t := New(rules)
	now := time.Unix(1_000_000, 0)
	t.now = func() time.Time { return now }
	return t, &now
}

// One message every five seconds: the first goes, the next is held for
// ~5s, and after 5s of simulated time it is released.
func TestOnePerFiveSeconds(t *testing.T) {
	th, clock := withClock([]Rule{{Match: "gmail.com", Limit: Limit{Rate: 0.2, Burst: 1}}})

	ok, _ := th.Reserve("gmail.com")
	if !ok {
		t.Fatal("first message should go immediately")
	}
	ok, wait := th.Reserve("gmail.com")
	if ok {
		t.Fatal("second message should be held")
	}
	if wait < 4*time.Second || wait > 5*time.Second {
		t.Errorf("wait = %v, want ~5s", wait)
	}

	// Not yet after 4s.
	*clock = clock.Add(4 * time.Second)
	if ok, _ := th.Reserve("gmail.com"); ok {
		t.Error("still throttled after 4s")
	}
	// Allowed after a full 5s.
	*clock = clock.Add(1 * time.Second)
	if ok, _ := th.Reserve("gmail.com"); !ok {
		t.Error("should be allowed after 5s")
	}
}

// Different destinations have independent buckets.
func TestPerDomainIsolation(t *testing.T) {
	th, _ := withClock([]Rule{{Match: "*", Limit: Limit{Rate: 0.2, Burst: 1}}})
	if ok, _ := th.Reserve("gmail.com"); !ok {
		t.Fatal("gmail first should pass")
	}
	if ok, _ := th.Reserve("outlook.com"); !ok {
		t.Error("a different domain must not be throttled by gmail's bucket")
	}
	if ok, _ := th.Reserve("gmail.com"); ok {
		t.Error("gmail second should be held")
	}
}

// A specific rule overrides the wildcard default.
func TestSpecificOverridesDefault(t *testing.T) {
	th, _ := withClock([]Rule{
		{Match: "*", Limit: Limit{Rate: 0.2, Burst: 1}},           // 1 / 5s default
		{Match: "gmail.com", Limit: Limit{Rate: 100, Burst: 100}}, // gmail: effectively free
	})
	for i := 0; i < 50; i++ {
		if ok, _ := th.Reserve("gmail.com"); !ok {
			t.Fatalf("gmail message %d should pass under its override", i+1)
		}
	}
	// A non-gmail domain still uses the strict default.
	if ok, _ := th.Reserve("slow.com"); !ok {
		t.Fatal("first slow.com passes")
	}
	if ok, _ := th.Reserve("slow.com"); ok {
		t.Error("slow.com is capped by the wildcard default")
	}
}

func TestBurst(t *testing.T) {
	th, _ := withClock([]Rule{{Match: "*", Limit: Limit{Rate: 1, Burst: 3}}})
	// Three in a burst.
	for i := 0; i < 3; i++ {
		if ok, _ := th.Reserve("x.com"); !ok {
			t.Fatalf("burst message %d should pass", i+1)
		}
	}
	if ok, _ := th.Reserve("x.com"); ok {
		t.Error("fourth exceeds the burst")
	}
}

func TestUnmatchedDomainUnthrottled(t *testing.T) {
	th, _ := withClock([]Rule{{Match: "gmail.com", Limit: Limit{Rate: 0.2, Burst: 1}}})
	// No "*" default: everything except gmail is free.
	for i := 0; i < 100; i++ {
		if ok, _ := th.Reserve("free.com"); !ok {
			t.Fatal("a domain with no matching rule must not be throttled")
		}
	}
}

func TestNilThrottle(t *testing.T) {
	var th *Throttle
	if ok, wait := th.Reserve("gmail.com"); !ok || wait != 0 {
		t.Error("nil throttle must allow everything")
	}
	if New(nil) != nil {
		t.Error("no rules must yield a nil throttle")
	}
}
