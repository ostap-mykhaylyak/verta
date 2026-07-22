package config

import (
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/pace"
)

// compileThrottle builds the scoped pacing configuration from the global
// queue.throttle rules and the per-domain / per-mailbox outbound.throttle
// rules. Invalid rules become warnings and are skipped.
func (c *Config) compileThrottle() {
	cfg := pace.Config{
		ByDomain:  map[string][]pace.Rule{},
		ByMailbox: map[string][]pace.Rule{},
	}

	for i, r := range c.Queue.Throttle {
		if pr, ok := c.paceRule(r, "queue.throttle", i); ok {
			if r.PerIP {
				cfg.PerIP = append(cfg.PerIP, pr)
			} else {
				cfg.Global = append(cfg.Global, pr)
			}
		}
	}
	for _, d := range c.Domains {
		for i, r := range d.Outbound.Throttle {
			if pr, ok := c.paceRule(r, "domain "+d.Name+" outbound.throttle", i); ok {
				cfg.ByDomain[d.Name] = append(cfg.ByDomain[d.Name], pr)
			}
		}
	}
	for _, u := range c.Users {
		if u.Outbound == nil {
			continue
		}
		for i, r := range u.Outbound.Throttle {
			if pr, ok := c.paceRule(r, "mailbox "+u.Email+" outbound.throttle", i); ok {
				cfg.ByMailbox[u.Email] = append(cfg.ByMailbox[u.Email], pr)
			}
		}
	}
	c.throttleConfig = cfg
}

// paceRule converts one ThrottleRule to a pace.Rule, warning and
// returning false on an invalid rule. The rate comes from `interval`
// ("one every 5s") or `messages`/`window`.
func (c *Config) paceRule(r ThrottleRule, where string, i int) (pace.Rule, bool) {
	if r.To == "" {
		c.warnf("%s[%d]: 'to' is required (a domain or \"*\"), rule ignored", where, i)
		return pace.Rule{}, false
	}
	var rate, burst float64
	burst = float64(r.Burst)
	switch {
	case r.Interval != "":
		d, err := time.ParseDuration(r.Interval)
		if err != nil || d <= 0 {
			c.warnf("%s[%d]: invalid 'interval' %q, rule ignored", where, i, r.Interval)
			return pace.Rule{}, false
		}
		rate = 1 / d.Seconds()
		if burst <= 0 {
			burst = 1
		}
	case r.Messages > 0:
		window := time.Hour
		if r.Window != "" {
			d, err := time.ParseDuration(r.Window)
			if err != nil || d <= 0 {
				c.warnf("%s[%d]: invalid 'window' %q, rule ignored", where, i, r.Window)
				return pace.Rule{}, false
			}
			window = d
		}
		rate = float64(r.Messages) / window.Seconds()
		if burst <= 0 {
			burst = float64(r.Messages)
		}
	default:
		c.warnf("%s[%d]: set 'interval' or 'messages', rule ignored", where, i)
		return pace.Rule{}, false
	}
	return pace.Rule{Match: r.To, Limit: pace.Limit{Rate: rate, Burst: burst}}, true
}

// ThrottleConfig returns the compiled scoped pacing configuration.
func (c *Config) ThrottleConfig() pace.Config { return c.throttleConfig }
