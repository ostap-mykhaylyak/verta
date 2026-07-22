// Package pace throttles outbound delivery to a maximum rate per
// destination — "no more than one message to gmail.com every five
// seconds" — so the queue drains at a speed the receiver tolerates
// instead of bursting and tripping the destination's own limits.
//
// It is a delay, not a rejection: a message that cannot go out yet stays
// in the queue and is released as soon as a token frees. A token bucket
// per destination domain gives the sustained rate, with an optional
// burst.
package pace

import (
	"strings"
	"sync"
	"time"
)

// Limit is a sustained rate (tokens per second) with a burst (bucket
// capacity). A burst of 1 spaces messages evenly at 1/Rate apart.
type Limit struct {
	Rate  float64
	Burst float64
}

// Rule maps a destination to a limit. Match is a destination domain, or
// "*" for the default applied to any domain without a specific rule.
type Rule struct {
	Match string
	Limit Limit
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Throttle paces deliveries per destination domain. A nil Throttle paces
// nothing.
type Throttle struct {
	mu      sync.Mutex
	limits  map[string]Limit // match -> limit ("*" = default)
	buckets map[string]*bucket
	now     func() time.Time // injectable for tests
}

// New builds a Throttle from the rules, or nil when there are none.
func New(rules []Rule) *Throttle {
	if len(rules) == 0 {
		return nil
	}
	t := &Throttle{
		limits:  make(map[string]Limit, len(rules)),
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
	for _, r := range rules {
		t.limits[strings.ToLower(r.Match)] = r.Limit
	}
	return t
}

// limitFor resolves the effective limit for a domain: its specific rule,
// else the "*" default, else none (unthrottled).
func (t *Throttle) limitFor(domain string) (Limit, bool) {
	if l, ok := t.limits[domain]; ok {
		return l, true
	}
	if l, ok := t.limits["*"]; ok {
		return l, true
	}
	return Limit{}, false
}

// Reserve consumes one token for domain when one is available now,
// returning (true, 0). Otherwise it returns (false, wait): the time
// until a token frees, after which the caller should retry the delivery.
// A denial does not consume a token.
func (t *Throttle) Reserve(domain string) (ok bool, wait time.Duration) {
	if t == nil {
		return true, 0
	}
	domain = strings.ToLower(domain)
	lim, has := t.limitFor(domain)
	if !has || lim.Rate <= 0 {
		return true, 0
	}
	burst := lim.Burst
	if burst < 1 {
		burst = 1
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	b := t.buckets[domain]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		t.buckets[domain] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * lim.Rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait = time.Duration((1 - b.tokens) / lim.Rate * float64(time.Second))
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return false, wait
}
