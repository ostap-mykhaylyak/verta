package ratelimit

import (
	"strings"
	"testing"
	"time"
)

func splitRcpt(r string) (string, string) {
	at := strings.LastIndex(r, "@")
	if at < 0 {
		return r, ""
	}
	return r, r[at+1:]
}

// A generic recipient_domain rule gives every destination domain its own
// bucket; an override for one domain replaces that domain's limit.
func TestGenericAndOverride(t *testing.T) {
	g := NewGovernor([]GovRule{
		{By: ByRecipientDomain, Window: time.Hour, Messages: 2},                     // generic: 2/h per domain
		{By: ByRecipientDomain, Match: "gmail.com", Window: time.Hour, Messages: 5}, // override: gmail 5/h
	})

	msg := func(dom string) bool {
		ok, _ := g.MsgAllowed(DirOutbound, Values{}, []string{"x@" + dom}, splitRcpt)
		return ok
	}

	// example.org: generic 2, third denied.
	if !msg("example.org") || !msg("example.org") || msg("example.org") {
		t.Error("generic per-domain limit of 2 not enforced")
	}
	// gmail.com: override 5, independent bucket.
	for i := 0; i < 5; i++ {
		if !msg("gmail.com") {
			t.Fatalf("gmail message %d should be allowed by the override", i+1)
		}
	}
	if msg("gmail.com") {
		t.Error("gmail override limit of 5 not enforced")
	}
}

// Distinct destination domains do not share a bucket.
func TestPerDomainIsolation(t *testing.T) {
	g := NewGovernor([]GovRule{{By: ByRecipientDomain, Window: time.Hour, Messages: 1}})
	a, _ := g.MsgAllowed(DirOutbound, Values{}, []string{"x@a.com"}, splitRcpt)
	b, _ := g.MsgAllowed(DirOutbound, Values{}, []string{"x@b.com"}, splitRcpt)
	if !a || !b {
		t.Error("different domains must have independent buckets")
	}
	again, _ := g.MsgAllowed(DirOutbound, Values{}, []string{"y@a.com"}, splitRcpt)
	if again {
		t.Error("a.com second message should be denied")
	}
}

// A message to several recipients in the same domain counts once for a
// recipient_domain message limit, but each recipient counts for a
// recipient-count limit.
func TestMessageVsRecipientCounters(t *testing.T) {
	g := NewGovernor([]GovRule{
		{By: ByRecipientDomain, Window: time.Hour, Messages: 1},
	})
	// One message, three gmail recipients: one message token consumed.
	ok, _ := g.MsgAllowed(DirOutbound, Values{},
		[]string{"a@gmail.com", "b@gmail.com", "c@gmail.com"}, splitRcpt)
	if !ok {
		t.Fatal("first message should pass")
	}
	// Next message to gmail is denied (bucket of 1 spent).
	if ok, _ := g.MsgAllowed(DirOutbound, Values{}, []string{"d@gmail.com"}, splitRcpt); ok {
		t.Error("second gmail message should be denied")
	}
}

func TestRecipientLimitAtRcptStage(t *testing.T) {
	g := NewGovernor([]GovRule{
		{By: ByRecipient, Window: time.Hour, Recipients: 2},
	})
	v := Values{Recipient: "victim@example.com", RecipientDomain: "example.com"}
	ok1, _ := g.RcptAllowed(DirInbound, v)
	ok2, _ := g.RcptAllowed(DirInbound, v)
	ok3, by := g.RcptAllowed(DirInbound, v)
	if !ok1 || !ok2 || ok3 {
		t.Errorf("per-recipient limit of 2 not enforced: %v %v %v", ok1, ok2, ok3)
	}
	if ok3 == false && by != ByRecipient {
		t.Errorf("denied dimension = %q, want %q", by, ByRecipient)
	}
}

// Direction scoping: an outbound-only rule must not fire on inbound.
func TestDirectionScoping(t *testing.T) {
	g := NewGovernor([]GovRule{
		{By: BySenderMailbox, Direction: DirOutbound, Window: time.Hour, Messages: 1},
	})
	v := Values{SenderMailbox: "mario@example.com", SenderDomain: "example.com"}
	// Inbound is unaffected.
	for i := 0; i < 3; i++ {
		if ok, _ := g.MsgAllowed(DirInbound, v, nil, splitRcpt); !ok {
			t.Fatal("inbound must ignore an outbound-only rule")
		}
	}
	// Outbound enforces it.
	if ok, _ := g.MsgAllowed(DirOutbound, v, nil, splitRcpt); !ok {
		t.Fatal("first outbound message should pass")
	}
	if ok, _ := g.MsgAllowed(DirOutbound, v, nil, splitRcpt); ok {
		t.Error("second outbound message should be denied")
	}
}

func TestNilGovernorAllows(t *testing.T) {
	var g *Governor
	if ok, _ := g.RcptAllowed(DirInbound, Values{Recipient: "x@y.z"}); !ok {
		t.Error("nil governor must allow recipients")
	}
	if ok, _ := g.MsgAllowed(DirInbound, Values{}, []string{"x@y.z"}, splitRcpt); !ok {
		t.Error("nil governor must allow messages")
	}
	if NewGovernor(nil) != nil {
		t.Error("no rules should compile to a nil governor")
	}
}
