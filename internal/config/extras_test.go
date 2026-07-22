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
