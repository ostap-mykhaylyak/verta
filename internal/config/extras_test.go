package config

import (
	"strings"
	"testing"
)

// The egress pool and the custom rate-limit rules must parse under
// KnownFields(true); an invalid rule is a warning, not a fatal error.
func TestEgressAndRateLimitRulesParse(t *testing.T) {
	y := minimal + `
egress:
  strategy: round_robin
  addresses:
    - address: 203.0.113.10
      helo: mail1.example.com
      bind: 10.1.0.20
      domains: [a.com]
rate_limit:
  rules:
    - by: recipient_domain
      messages: 200
    - by: sender_mailbox
      match: x@a.com
      direction: outbound
      messages: 5000
    - by: bogus_dim
      messages: 1
`
	cfg, err := Load(write(t, y, oneDomain))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Egress.Strategy != "round_robin" || len(cfg.Egress.Addresses) != 1 {
		t.Fatalf("egress = %+v", cfg.Egress)
	}
	if cfg.Egress.Addresses[0].Bind != "10.1.0.20" || cfg.Egress.Addresses[0].HELO != "mail1.example.com" {
		t.Errorf("egress address = %+v", cfg.Egress.Addresses[0])
	}
	// Two valid rules compile; the bogus dimension is dropped with a warning.
	if n := len(cfg.GovernorRules()); n != 2 {
		t.Errorf("compiled rules = %d, want 2", n)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bogus_dim") {
			found = true
		}
	}
	if !found {
		t.Errorf("want a warning naming the bogus dimension, got %v", cfg.Warnings)
	}
}

// queue.throttle must compile to pace rules, converting messages/window
// into a per-second rate; an invalid rule warns and is skipped.
func TestThrottleRulesParse(t *testing.T) {
	y := minimal + `
queue:
  dir: /tmp/q
  throttle:
    - to: gmail.com
      messages: 1
      window: 5s
    - to: "*"
      messages: 60
      window: 1m
    - to: broken.com
      messages: 0
`
	cfg, err := Load(write(t, y, oneDomain))
	if err != nil {
		t.Fatal(err)
	}
	rules := cfg.ThrottleRules()
	if len(rules) != 2 {
		t.Fatalf("compiled throttle rules = %d, want 2 (broken skipped)", len(rules))
	}
	// gmail: 1 per 5s => 0.2/s.
	for _, r := range rules {
		if r.Match == "gmail.com" && (r.Limit.Rate < 0.19 || r.Limit.Rate > 0.21) {
			t.Errorf("gmail rate = %v, want ~0.2/s", r.Limit.Rate)
		}
	}
}
