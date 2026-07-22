package filter

import (
	"strings"
	"testing"
)

func msg(from, to, subject, body string) []byte {
	return []byte("From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject +
		"\r\n\r\n" + body + "\r\n")
}

func TestFolderBySender(t *testing.T) {
	rules := []Rule{{From: "newsletter@", Folder: "Newsletters", Stop: true}}
	out := Apply(rules, msg("The Newsletter@brand.com", "me@ex.com", "Deals", "hi"))
	if out.Folder != "Newsletters" {
		t.Errorf("folder = %q, want Newsletters", out.Folder)
	}
}

func TestConditionsAreAnded(t *testing.T) {
	// Both From and Subject must match.
	rules := []Rule{{From: "boss@ex.com", Subject: "urgent", Flagged: true}}
	if out := Apply(rules, msg("boss@ex.com", "me@ex.com", "lunch?", "x")); out.Flagged {
		t.Error("must not flag when subject does not match")
	}
	if out := Apply(rules, msg("boss@ex.com", "me@ex.com", "URGENT: call", "x")); !out.Flagged {
		t.Error("must flag when both from and subject match")
	}
}

func TestFirstStopWins_ButActionsAccumulate(t *testing.T) {
	rules := []Rule{
		{From: "boss@ex.com", Flagged: true},            // no stop: keep going
		{Subject: "report", Folder: "Work", Stop: true}, // stop here
		{Subject: "report", Seen: true},                 // never reached
	}
	out := Apply(rules, msg("boss@ex.com", "me@ex.com", "Weekly report", "x"))
	if !out.Flagged || out.Folder != "Work" {
		t.Errorf("actions should accumulate up to stop: %+v", out)
	}
	if out.Seen {
		t.Error("rule after the matching stop must not run")
	}
}

func TestToMatchesCc(t *testing.T) {
	m := []byte("From: a@ex.com\r\nTo: x@ex.com\r\nCc: sales@ex.com\r\nSubject: s\r\n\r\nb\r\n")
	out := Apply([]Rule{{To: "sales@ex.com", Folder: "Sales"}}, m)
	if out.Folder != "Sales" {
		t.Errorf("Cc should satisfy a To condition: %+v", out)
	}
}

func TestLargerThanAndJunkAndForward(t *testing.T) {
	big := msg("spam@bad.com", "me@ex.com", "cheap", strings.Repeat("x", 5000))
	out := Apply([]Rule{{From: "spam@bad.com", LargerThan: 1000, Junk: true}}, big)
	if !out.Junk {
		t.Errorf("large spam should be junked: %+v", out)
	}
	small := msg("spam@bad.com", "me@ex.com", "cheap", "x")
	if Apply([]Rule{{From: "spam@bad.com", LargerThan: 1000, Junk: true}}, small).Junk {
		t.Error("a small message must not match larger_than")
	}

	fwd := Apply([]Rule{{To: "team@ex.com", ForwardTo: "boss@ex.com"}},
		[]byte("From: a@x.com\r\nTo: team@ex.com\r\nSubject: s\r\n\r\nb\r\n"))
	if len(fwd.Forward) != 1 || fwd.Forward[0] != "boss@ex.com" {
		t.Errorf("forward not collected: %+v", fwd)
	}
}

func TestHeaderCondition(t *testing.T) {
	m := []byte("From: a@ex.com\r\nTo: me@ex.com\r\nSubject: s\r\nX-Mailer: sendgrid\r\n\r\nb\r\n")
	out := Apply([]Rule{{Header: "X-Mailer: sendgrid", Folder: "Bulk"}}, m)
	if out.Folder != "Bulk" {
		t.Errorf("header condition should match: %+v", out)
	}
}

func TestNoRulesIsInbox(t *testing.T) {
	out := Apply(nil, msg("a@ex.com", "me@ex.com", "hi", "x"))
	if out.Folder != "" || out.Junk || out.Discard || out.Flagged || out.Seen {
		t.Errorf("no rules must be a clean INBOX delivery: %+v", out)
	}
}
