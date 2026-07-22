package ratelimit

import "time"

// Dimensions a custom rate-limit rule can key on. The value is taken
// from the current SMTP transaction.
const (
	ByIP              = "ip"               // connecting source IP
	BySenderDomain    = "sender_domain"    // domain of MAIL FROM / the authed user
	BySenderMailbox   = "sender_mailbox"   // full MAIL FROM / authed address
	ByRecipient       = "recipient"        // full RCPT TO address
	ByRecipientDomain = "recipient_domain" // domain of RCPT TO
)

// Directions a rule applies to. Empty means both.
const (
	DirInbound  = "inbound"  // port 25
	DirOutbound = "outbound" // authenticated submission
)

// GovRule is one configured custom limit. Match empty makes it a generic
// rule (every value of the dimension gets its own bucket of this size);
// Match set makes it an override for exactly that value, replacing the
// generic limit for it. A zero Messages or Recipients means that counter
// is unlimited.
type GovRule struct {
	By         string
	Match      string
	Direction  string
	Window     time.Duration
	Messages   int
	Recipients int
}

// Values carries the transaction attributes a rule keys on.
type Values struct {
	IP              string
	SenderMailbox   string
	SenderDomain    string
	Recipient       string
	RecipientDomain string
}

func (v Values) get(dim string) string {
	switch dim {
	case ByIP:
		return v.IP
	case BySenderDomain:
		return v.SenderDomain
	case BySenderMailbox:
		return v.SenderMailbox
	case ByRecipient:
		return v.Recipient
	case ByRecipientDomain:
		return v.RecipientDomain
	}
	return ""
}

// keyed is one counter for one dimension: a generic bucket family plus
// per-value overrides. An override replaces the generic limit for its
// value; anything else falls back to the generic (or is unlimited).
type keyed struct {
	generic *Limiter
	over    map[string]*Limiter
}

func (k *keyed) allow(value string) bool {
	if k == nil || value == "" {
		return true
	}
	if l := k.over[value]; l != nil {
		return l.Allow(value)
	}
	if k.generic != nil {
		return k.generic.Allow(value)
	}
	return true
}

// dimCounters holds the message and recipient keyed limits of one
// dimension, for one direction.
type dimCounters struct {
	msgs  *keyed
	rcpts *keyed
}

// Governor evaluates the custom per-dimension rate-limit rules. A nil
// Governor (no rules configured) allows everything.
type Governor struct {
	// dims[direction][dimension]
	dims map[string]map[string]*dimCounters
}

// NewGovernor compiles the rules. Rules with an empty direction apply to
// both inbound and outbound.
func NewGovernor(rules []GovRule) *Governor {
	if len(rules) == 0 {
		return nil
	}
	g := &Governor{dims: map[string]map[string]*dimCounters{
		DirInbound:  {},
		DirOutbound: {},
	}}
	for _, r := range rules {
		window := r.Window
		if window <= 0 {
			window = time.Hour
		}
		dirs := []string{r.Direction}
		if r.Direction == "" {
			dirs = []string{DirInbound, DirOutbound}
		}
		for _, dir := range dirs {
			byDim := g.dims[dir]
			if byDim == nil {
				continue // unknown direction: ignore
			}
			dc := byDim[r.By]
			if dc == nil {
				dc = &dimCounters{}
				byDim[r.By] = dc
			}
			if r.Messages > 0 {
				add(&dc.msgs, r.Match, r.Messages, window)
			}
			if r.Recipients > 0 {
				add(&dc.rcpts, r.Match, r.Recipients, window)
			}
		}
	}
	return g
}

// add installs a limiter into a keyed set as the generic bucket (match
// empty) or a specific override.
func add(k **keyed, match string, limit int, window time.Duration) {
	if *k == nil {
		*k = &keyed{over: map[string]*Limiter{}}
	}
	l := New(limit, window)
	if match == "" {
		(*k).generic = l
	} else {
		(*k).over[match] = l
	}
}

// RcptAllowed consumes one recipient token from every dimension that
// carries a recipient limit for this direction. It returns the first
// dimension that denied, or "" when the recipient is allowed.
func (g *Governor) RcptAllowed(direction string, v Values) (ok bool, deniedBy string) {
	if g == nil {
		return true, ""
	}
	byDim := g.dims[direction]
	for dim, dc := range byDim {
		if !dc.rcpts.allow(v.get(dim)) {
			return false, dim
		}
	}
	return true, ""
}

// MsgAllowed consumes one message token per distinct key: once for the
// sender/IP dimensions, and once per distinct recipient (or recipient
// domain) among the transaction's recipients. It is checked before the
// message body is accepted. rcptOf splits a recipient into its full
// address and its domain.
func (g *Governor) MsgAllowed(direction string, v Values, recipients []string, rcptOf func(string) (addr, domain string)) (ok bool, deniedBy string) {
	if g == nil {
		return true, ""
	}
	byDim := g.dims[direction]
	for dim, dc := range byDim {
		switch dim {
		case ByIP, BySenderDomain, BySenderMailbox:
			if !dc.msgs.allow(v.get(dim)) {
				return false, dim
			}
		case ByRecipient, ByRecipientDomain:
			seen := map[string]bool{}
			for _, r := range recipients {
				addr, domain := rcptOf(r)
				val := addr
				if dim == ByRecipientDomain {
					val = domain
				}
				if seen[val] {
					continue
				}
				seen[val] = true
				if !dc.msgs.allow(val) {
					return false, dim
				}
			}
		}
	}
	return true, ""
}
