package egress

import "testing"

func pool(strategy string) *Pool {
	return New(strategy, []Address{
		{Public: "203.0.113.10", HELO: "mail1.example.com", Bind: "10.1.0.20", Domains: []string{"clientea.com"}},
		{Public: "203.0.113.11", HELO: "mail2.example.com", Bind: "10.1.0.21", Domains: []string{"clientb.com"}},
	})
}

// The default (recipient_domain) strategy is sticky: a given destination
// domain always resolves to the same source, and it binds the internal
// address with its matching HELO.
func TestRecipientDomainSticky(t *testing.T) {
	p := pool(StrategyRecipientDomain)
	first := p.Select("a@ours.com", "gmail.com")
	for i := 0; i < 20; i++ {
		if got := p.Select("b@ours.com", "gmail.com"); got != first {
			t.Fatalf("gmail must be sticky: %+v vs %+v", got, first)
		}
	}
	// A bind and its HELO travel together.
	if first.Bind != "10.1.0.20" && first.Bind != "10.1.0.21" {
		t.Errorf("bind not an internal address: %q", first.Bind)
	}
	if first.HELO == "" {
		t.Error("HELO must be set")
	}
	// Different domains can (and here do) split across both IPs.
	other := p.Select("a@ours.com", "outlook.com")
	if other == first {
		t.Log("outlook hashed to the same IP as gmail (allowed, just unlucky)")
	}
}

// sender_domain pins each hosted domain to its mapped IP.
func TestSenderDomainMapping(t *testing.T) {
	p := pool(StrategySenderDomain)
	a := p.Select("user@clientea.com", "anywhere.com")
	if a.Bind != "10.1.0.20" || a.HELO != "mail1.example.com" {
		t.Errorf("clientea.com should map to the first IP: %+v", a)
	}
	b := p.Select("user@clientb.com", "anywhere.com")
	if b.Bind != "10.1.0.21" {
		t.Errorf("clientb.com should map to the second IP: %+v", b)
	}
}

// round_robin advances through the pool per call.
func TestRoundRobin(t *testing.T) {
	p := pool(StrategyRoundRobin)
	a := p.Select("x@y.z", "d1.com")
	b := p.Select("x@y.z", "d2.com")
	c := p.Select("x@y.z", "d3.com")
	if a == b {
		t.Error("round robin should advance between the first two")
	}
	if a != c {
		t.Error("round robin should wrap back after two addresses")
	}
}

// Bind defaults to Public when not set (plain host, no NAT).
func TestBindDefaultsToPublic(t *testing.T) {
	p := New(StrategyRoundRobin, []Address{{Public: "198.51.100.5", HELO: "mx.example.com"}})
	if s := p.Select("a@b.c", "d.e"); s.Bind != "198.51.100.5" {
		t.Errorf("bind should default to the public IP, got %q", s.Bind)
	}
}

func TestNilPool(t *testing.T) {
	if New(StrategyRoundRobin, nil) != nil {
		t.Error("empty address list must yield a nil pool")
	}
	var p *Pool
	if got := p.Select("a@b.c", "d.e"); got != (Source{}) {
		t.Errorf("nil pool must return the zero Source, got %+v", got)
	}
}

// ByAddress finds a specific pool address, for a domain/mailbox pin.
func TestByAddress(t *testing.T) {
	p := pool(StrategyRoundRobin)
	s, ok := p.ByAddress("203.0.113.11")
	if !ok || s.Bind != "10.1.0.21" || s.HELO != "mail2.example.com" {
		t.Errorf("ByAddress = %+v, %v", s, ok)
	}
	if _, ok := p.ByAddress("198.51.100.9"); ok {
		t.Error("unknown address must not resolve")
	}
	var nilp *Pool
	if _, ok := nilp.ByAddress("x"); ok {
		t.Error("nil pool ByAddress must be false")
	}
}
