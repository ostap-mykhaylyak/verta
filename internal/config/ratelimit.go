package config

import (
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/ratelimit"
)

// govRules is the compiled form of RateLimit.Rules, built once at load.
// Unexported: it never round-trips through YAML.
var validRateLimitDims = map[string]bool{
	ratelimit.ByIP:              true,
	ratelimit.BySenderDomain:    true,
	ratelimit.BySenderMailbox:   true,
	ratelimit.ByRecipient:       true,
	ratelimit.ByRecipientDomain: true,
}

// compileRateLimitRules validates each custom rule and stores the ones
// that hold together. An invalid rule (unknown dimension or direction,
// bad window, no counters) becomes a warning and is skipped, matching
// the "one bad entry does not take the server down" rule.
func (c *Config) compileRateLimitRules() {
	c.govRules = c.govRules[:0]
	for i, r := range c.RateLimit.Rules {
		if !validRateLimitDims[r.By] {
			c.warnf("rate_limit.rules[%d]: unknown 'by' %q, rule ignored", i, r.By)
			continue
		}
		if r.Direction != "" && r.Direction != ratelimit.DirInbound && r.Direction != ratelimit.DirOutbound {
			c.warnf("rate_limit.rules[%d]: 'direction' must be inbound or outbound, rule ignored", i)
			continue
		}
		window := time.Hour
		if r.Window != "" {
			d, err := time.ParseDuration(r.Window)
			if err != nil || d <= 0 {
				c.warnf("rate_limit.rules[%d]: invalid 'window' %q, rule ignored", i, r.Window)
				continue
			}
			window = d
		}
		if r.Messages <= 0 && r.Recipients <= 0 {
			c.warnf("rate_limit.rules[%d]: neither 'messages' nor 'recipients' set, rule ignored", i)
			continue
		}
		c.govRules = append(c.govRules, ratelimit.GovRule{
			By:         r.By,
			Match:      r.Match,
			Direction:  r.Direction,
			Window:     window,
			Messages:   r.Messages,
			Recipients: r.Recipients,
		})
	}

	// Per-domain and per-mailbox outbound rate caps become outbound
	// sender-scoped override rules (per hour), so the same Governor
	// enforces them alongside the global rules.
	for _, d := range c.Domains {
		if r := d.Outbound.Rate; r.MessagesPerHour > 0 || r.RecipientsPerHour > 0 {
			c.govRules = append(c.govRules, ratelimit.GovRule{
				By: ratelimit.BySenderDomain, Match: d.Name, Direction: ratelimit.DirOutbound,
				Window: time.Hour, Messages: r.MessagesPerHour, Recipients: r.RecipientsPerHour,
			})
		}
	}
	for _, u := range c.Users {
		if u.Outbound == nil {
			continue
		}
		if r := u.Outbound.Rate; r.MessagesPerHour > 0 || r.RecipientsPerHour > 0 {
			c.govRules = append(c.govRules, ratelimit.GovRule{
				By: ratelimit.BySenderMailbox, Match: u.Email, Direction: ratelimit.DirOutbound,
				Window: time.Hour, Messages: r.MessagesPerHour, Recipients: r.RecipientsPerHour,
			})
		}
	}
}

// GovernorRules returns the compiled custom rate-limit rules.
func (c *Config) GovernorRules() []ratelimit.GovRule { return c.govRules }
