// Package filter applies simple, per-mailbox delivery rules: it matches
// an incoming message on a few fields and decides where it lands and how
// it is flagged. It is deliberately NOT Sieve — a small, legible set of
// conditions and actions that covers the common cases (sort a
// newsletter into a folder, drop obvious junk, flag mail from the boss),
// declared right next to the mailbox in the domain's YAML.
//
// A rule's conditions are ANDed: every condition that is set must match.
// Rules are evaluated top to bottom; the first rule with "stop: true"
// that matches ends evaluation. Actions accumulate across matching rules
// until then, so a rule can flag while a later one files into a folder.
package filter

import (
	"bytes"
	"net/mail"
	"strings"
)

// Rule is one delivery rule: some conditions and the actions to take
// when they all match.
type Rule struct {
	// --- conditions (empty/zero means "don't care") ---
	// From matches a substring of the From header, case-insensitive.
	From string `yaml:"from"`
	// To matches a substring of the To or Cc headers (so a rule can key
	// on the alias a message was addressed to).
	To string `yaml:"to"`
	// Subject matches a substring of the Subject header.
	Subject string `yaml:"subject"`
	// Header matches an arbitrary header, written "Name: substring".
	// The name is matched exactly (case-insensitive), the value as a
	// substring.
	Header string `yaml:"header"`
	// LargerThan matches messages strictly larger than this many bytes.
	LargerThan int64 `yaml:"larger_than"`

	// --- actions ---
	// Folder files the message into this mailbox folder (created on
	// demand). Empty leaves it in INBOX.
	Folder string `yaml:"folder"`
	// Junk files the message into the Spam folder (\Junk special-use).
	Junk bool `yaml:"junk"`
	// Seen marks the message read on delivery.
	Seen bool `yaml:"seen"`
	// Flagged marks the message flagged/important on delivery.
	Flagged bool `yaml:"flagged"`
	// ForwardTo sends a copy to another address (subject to the same
	// SRS/relay path as a mailbox forward).
	ForwardTo string `yaml:"forward_to"`
	// Discard drops the message silently: it is accepted on the wire
	// (no bounce) but never stored. Use with care.
	Discard bool `yaml:"discard"`
	// Stop ends rule evaluation once this rule has matched.
	Stop bool `yaml:"stop"`
}

// Outcome is the accumulated decision of a rule set for one message.
// The zero Outcome means "deliver to INBOX, unflagged" — the default
// when no rule matches.
type Outcome struct {
	// Folder is the destination folder ("" = INBOX). Junk overrides it.
	Folder string
	// Junk routes to the Spam folder.
	Junk bool
	// Seen and Flagged are the flags to set on the stored message.
	Seen    bool
	Flagged bool
	// Forward lists addresses to send a copy to.
	Forward []string
	// Discard drops the message without storing it.
	Discard bool
}

// Apply evaluates rules against a raw message and returns the combined
// outcome. Header parsing failures are non-fatal: a message whose
// headers cannot be read simply matches no header condition.
func Apply(rules []Rule, msg []byte) Outcome {
	h := parseHeader(msg)
	size := int64(len(msg))
	var out Outcome

	for _, r := range rules {
		if !r.matches(h, size) {
			continue
		}
		if r.Folder != "" {
			out.Folder = r.Folder
		}
		if r.Junk {
			out.Junk = true
		}
		if r.Seen {
			out.Seen = true
		}
		if r.Flagged {
			out.Flagged = true
		}
		if r.ForwardTo != "" {
			out.Forward = append(out.Forward, r.ForwardTo)
		}
		if r.Discard {
			out.Discard = true
		}
		if r.Stop {
			break
		}
	}
	return out
}

// matches reports whether every set condition of the rule is satisfied.
func (r Rule) matches(h mail.Header, size int64) bool {
	if r.From != "" && !containsFold(h.Get("From"), r.From) {
		return false
	}
	if r.To != "" && !containsFold(h.Get("To"), r.To) && !containsFold(h.Get("Cc"), r.To) {
		return false
	}
	if r.Subject != "" && !containsFold(h.Get("Subject"), r.Subject) {
		return false
	}
	if r.Header != "" {
		name, want, ok := strings.Cut(r.Header, ":")
		if !ok {
			return false
		}
		if !containsFold(h.Get(strings.TrimSpace(name)), strings.TrimSpace(want)) {
			return false
		}
	}
	if r.LargerThan > 0 && size <= r.LargerThan {
		return false
	}
	// A rule with no conditions at all is a catch-all (e.g. a blanket
	// "forward everything"); that is intentional, so it matches.
	return true
}

// containsFold reports whether s contains sub, case-insensitively.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// parseHeader reads just the header block; a body is not needed.
func parseHeader(msg []byte) mail.Header {
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return mail.Header{}
	}
	return m.Header
}
