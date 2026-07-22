// Package pace throttles outbound delivery to a maximum rate, holding
// messages in the queue and releasing them as tokens free (a delay, not
// a rejection). Rates apply at four independent scopes:
//
//   - global: one limit per destination domain, across the whole queue;
//   - per sender domain / per sender mailbox: a hosted domain or a single
//     mailbox has its own pace toward a destination;
//   - per egress IP: each outbound source IP paces itself toward a
//     destination.
//
// The sender scopes are a precedence (mailbox beats domain beats global:
// the most specific one that has a rule for the destination wins). The
// per-IP scope is independent and applies on top — a delivery must have
// a free token in both its sender-scoped bucket and its egress-IP bucket,
// and waits for the longer of the two.
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
// "*" for the default within its scope.
type Rule struct {
	Match string
	Limit Limit
}

// Config groups the rules by the scope they apply to. All maps are keyed
// lowercase.
type Config struct {
	Global    []Rule            // per destination, across the queue
	PerIP     []Rule            // per egress IP (independent)
	ByDomain  map[string][]Rule // sender domain -> rules
	ByMailbox map[string][]Rule // sender mailbox -> rules
}

// Key identifies one delivery for throttling.
type Key struct {
	Mailbox  string // envelope sender (full address)
	Domain   string // envelope sender domain
	EgressIP string // resolved outbound source IP ("" = none)
	Dest     string // destination domain
}

// ruleset resolves a destination to its limit within one scope.
type ruleset map[string]Limit

func (rs ruleset) lookup(dest string) (Limit, bool) {
	if rs == nil {
		return Limit{}, false
	}
	if l, ok := rs[dest]; ok {
		return l, true
	}
	if l, ok := rs["*"]; ok {
		return l, true
	}
	return Limit{}, false
}

func toRuleset(rules []Rule) ruleset {
	if len(rules) == 0 {
		return nil
	}
	rs := make(ruleset, len(rules))
	for _, r := range rules {
		rs[strings.ToLower(r.Match)] = r.Limit
	}
	return rs
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Throttle enforces the configured rules. A nil Throttle paces nothing.
type Throttle struct {
	mu      sync.Mutex
	global  ruleset
	perIP   ruleset
	byDom   map[string]ruleset
	byMbx   map[string]ruleset
	buckets map[string]*bucket
	now     func() time.Time
}

// New builds a Throttle, or nil when no scope has any rule.
func New(c Config) *Throttle {
	t := &Throttle{
		global:  toRuleset(c.Global),
		perIP:   toRuleset(c.PerIP),
		byDom:   map[string]ruleset{},
		byMbx:   map[string]ruleset{},
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
	for d, rules := range c.ByDomain {
		if rs := toRuleset(rules); rs != nil {
			t.byDom[strings.ToLower(d)] = rs
		}
	}
	for m, rules := range c.ByMailbox {
		if rs := toRuleset(rules); rs != nil {
			t.byMbx[strings.ToLower(m)] = rs
		}
	}
	if t.global == nil && t.perIP == nil && len(t.byDom) == 0 && len(t.byMbx) == 0 {
		return nil
	}
	return t
}

// applicable returns the (bucketKey, limit) pairs a delivery must satisfy:
// the most specific sender scope with a rule for the destination, plus the
// per-IP scope when configured.
func (t *Throttle) applicable(k Key) []scoped {
	dest := strings.ToLower(k.Dest)
	var out []scoped

	// Sender scope: mailbox, else domain, else global.
	if rs := t.byMbx[strings.ToLower(k.Mailbox)]; rs != nil {
		if l, ok := rs.lookup(dest); ok {
			out = append(out, scoped{"mbx:" + strings.ToLower(k.Mailbox) + "|" + dest, l})
		}
	}
	if len(out) == 0 {
		if rs := t.byDom[strings.ToLower(k.Domain)]; rs != nil {
			if l, ok := rs.lookup(dest); ok {
				out = append(out, scoped{"dom:" + strings.ToLower(k.Domain) + "|" + dest, l})
			}
		}
	}
	if len(out) == 0 {
		if l, ok := t.global.lookup(dest); ok {
			out = append(out, scoped{"g|" + dest, l})
		}
	}

	// Per-IP scope, independent.
	if k.EgressIP != "" {
		if l, ok := t.perIP.lookup(dest); ok {
			out = append(out, scoped{"ip:" + k.EgressIP + "|" + dest, l})
		}
	}
	return out
}

type scoped struct {
	key   string
	limit Limit
}

// Reserve consumes one token from every bucket that applies to the
// delivery when all have one available, returning (true, 0). Otherwise
// it consumes nothing and returns (false, wait) for the longest wait.
func (t *Throttle) Reserve(k Key) (ok bool, wait time.Duration) {
	if t == nil {
		return true, 0
	}
	buckets := t.applicable(k)
	if len(buckets) == 0 {
		return true, 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()

	// First pass: refill and find the longest wait if any bucket is dry.
	var maxWait time.Duration
	blocked := false
	for _, s := range buckets {
		b := t.refill(s.key, s.limit, now)
		if b.tokens < 1 {
			blocked = true
			w := time.Duration((1 - b.tokens) / s.limit.Rate * float64(time.Second))
			if w < time.Millisecond {
				w = time.Millisecond
			}
			if w > maxWait {
				maxWait = w
			}
		}
	}
	if blocked {
		return false, maxWait
	}
	// Second pass: all have a token, consume from each.
	for _, s := range buckets {
		t.buckets[s.key].tokens--
	}
	return true, 0
}

// refill advances a bucket to now and returns it (creating it full).
func (t *Throttle) refill(key string, lim Limit, now time.Time) *bucket {
	burst := lim.Burst
	if burst < 1 {
		burst = 1
	}
	b := t.buckets[key]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		t.buckets[key] = b
		return b
	}
	b.tokens += now.Sub(b.last).Seconds() * lim.Rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	return b
}
