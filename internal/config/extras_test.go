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
	rules := cfg.ThrottleConfig().Global
	if len(rules) != 2 {
		t.Fatalf("compiled global throttle rules = %d, want 2 (broken skipped)", len(rules))
	}
	// gmail: 1 per 5s => 0.2/s.
	for _, r := range rules {
		if r.Match == "gmail.com" && (r.Limit.Rate < 0.19 || r.Limit.Rate > 0.21) {
			t.Errorf("gmail rate = %v, want ~0.2/s", r.Limit.Rate)
		}
	}
}

// Per-domain and per-mailbox outbound policy must parse and compile into
// egress pins, governor rate overrides, and scoped pacing.
func TestPerDomainMailboxOutbound(t *testing.T) {
	dom := `name: clientea.com
outbound:
  egress_ip: 203.0.113.10
  rate:
    messages_per_hour: 1000
  throttle:
    - to: gmail.com
      interval: 5s
users:
  - email: bulk@clientea.com
    maildir: /var/mail/bulk
    outbound:
      egress_ip: 203.0.113.11
      rate:
        messages_per_hour: 20000
      throttle:
        - to: gmail.com
          interval: 2s
`
	cfg, err := Load(write(t, minimal, map[string]string{"clientea.com": dom}))
	if err != nil {
		t.Fatal(err)
	}
	// Egress pins parsed.
	if cfg.Domains[0].Outbound.EgressIP != "203.0.113.10" {
		t.Errorf("domain egress_ip = %q", cfg.Domains[0].Outbound.EgressIP)
	}
	if cfg.Users[0].Outbound == nil || cfg.Users[0].Outbound.EgressIP != "203.0.113.11" {
		t.Errorf("mailbox egress_ip = %+v", cfg.Users[0].Outbound)
	}
	// Rate overrides became outbound governor rules (sender_domain + sender_mailbox).
	var dom1000, mbx20000 bool
	for _, r := range cfg.GovernorRules() {
		if r.By == "sender_domain" && r.Match == "clientea.com" && r.Messages == 1000 && r.Direction == "outbound" {
			dom1000 = true
		}
		if r.By == "sender_mailbox" && r.Match == "bulk@clientea.com" && r.Messages == 20000 {
			mbx20000 = true
		}
	}
	if !dom1000 || !mbx20000 {
		t.Errorf("rate overrides not compiled: domain=%v mailbox=%v", dom1000, mbx20000)
	}
	// Throttle scoped per domain and per mailbox.
	tc := cfg.ThrottleConfig()
	if len(tc.ByDomain["clientea.com"]) != 1 {
		t.Errorf("domain throttle = %+v", tc.ByDomain)
	}
	if len(tc.ByMailbox["bulk@clientea.com"]) != 1 {
		t.Errorf("mailbox throttle = %+v", tc.ByMailbox)
	}
	// interval 2s => 0.5/s for the mailbox rule.
	if r := tc.ByMailbox["bulk@clientea.com"][0]; r.Limit.Rate < 0.49 || r.Limit.Rate > 0.51 {
		t.Errorf("mailbox interval rate = %v, want ~0.5/s", r.Limit.Rate)
	}
}

// Domain and mailbox quotas parse to bytes; the helpers resolve limits
// and the domain's mailbox list; a bad quota warns rather than failing.
func TestQuotaConfig(t *testing.T) {
	dom := `name: clientea.com
quota: 10G
users:
  - email: a@clientea.com
    maildir: /var/mail/a
    quota: 2G
  - email: b@clientea.com
    maildir: /var/mail/b
    quota: nonsense
`
	cfg, err := Load(write(t, minimal, map[string]string{"clientea.com": dom}))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.DomainQuota("clientea.com"); got != 10<<30 {
		t.Errorf("domain quota = %d, want %d", got, int64(10)<<30)
	}
	if got := cfg.UserQuota("a@clientea.com"); got != 2<<30 {
		t.Errorf("mailbox a quota = %d, want %d", got, int64(2)<<30)
	}
	if got := cfg.UserQuota("b@clientea.com"); got != 0 {
		t.Errorf("malformed mailbox quota must be 0 (unlimited), got %d", got)
	}
	dirs := cfg.DomainMaildirs("clientea.com")
	if len(dirs) != 2 {
		t.Errorf("domain maildirs = %v, want 2", dirs)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nonsense") {
			found = true
		}
	}
	if !found {
		t.Errorf("a malformed quota must warn: %v", cfg.Warnings)
	}
}
