package config

import (
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/pace"
)

// compileThrottleRules validates the queue pacing rules and stores the
// ones that hold together. An invalid rule (missing target, bad window,
// no rate) becomes a warning and is skipped.
func (c *Config) compileThrottleRules() {
	c.throttleRules = c.throttleRules[:0]
	for i, r := range c.Queue.Throttle {
		if r.To == "" {
			c.warnf("queue.throttle[%d]: 'to' is required (a domain or \"*\"), rule ignored", i)
			continue
		}
		if r.Messages <= 0 {
			c.warnf("queue.throttle[%d]: 'messages' must be > 0, rule ignored", i)
			continue
		}
		window := time.Hour
		if r.Window != "" {
			d, err := time.ParseDuration(r.Window)
			if err != nil || d <= 0 {
				c.warnf("queue.throttle[%d]: invalid 'window' %q, rule ignored", i, r.Window)
				continue
			}
			window = d
		}
		burst := float64(r.Burst)
		if burst <= 0 {
			burst = float64(r.Messages)
		}
		c.throttleRules = append(c.throttleRules, pace.Rule{
			Match: r.To,
			Limit: pace.Limit{
				Rate:  float64(r.Messages) / window.Seconds(),
				Burst: burst,
			},
		})
	}
}

// ThrottleRules returns the compiled outbound pacing rules.
func (c *Config) ThrottleRules() []pace.Rule { return c.throttleRules }
