// Package routing expands a recipient address into a delivery plan: the
// local mailboxes it lands in and the external addresses it is forwarded
// to. It unifies four features on top of the plain "one address, one
// mailbox" model:
//
//   - aliases: a local part maps to one or more targets, local or remote;
//   - distribution lists: an alias with several local targets;
//   - forwarding: a mailbox (or alias) whose target is off-server, sent
//     out through SRS + the relay queue;
//   - catch-all: a domain-wide fallback for otherwise-unknown addresses.
//
// Resolution is recursive (an alias may point at another alias or at a
// forwarding mailbox) with loop and depth protection, so a cycle or a
// self-referential alias can never fan out without bound.
package routing

import (
	"strings"

	"github.com/ostap-mykhaylyak/verta/internal/config"
	"github.com/ostap-mykhaylyak/verta/internal/filter"
	"github.com/ostap-mykhaylyak/verta/internal/srs"
	"github.com/ostap-mykhaylyak/verta/internal/storage"
)

// maxDepth caps alias/forward recursion.
const maxDepth = 10

// Local is one local delivery: a mailbox plus the filter rules to apply
// when a message is stored into it.
type Local struct {
	Mailbox storage.Mailbox
	Filters []filter.Rule
}

// Plan is the full set of destinations for one recipient.
type Plan struct {
	// Local mailboxes to store into.
	Local []Local
	// Remote addresses to relay to (forwards).
	Remote []string
	// Found reports whether the address is deliverable at all. False
	// means "no such user here" — the caller rejects the recipient.
	Found bool
}

// Resolve builds the delivery plan for email. srsSecret enables the SRS
// bounce-return path (an incoming SRS address is reversed to its
// original sender); pass "" to disable it.
func Resolve(cfg *config.Config, srsSecret, email string) Plan {
	local, domain, ok := storage.Split(email)
	if !ok {
		return Plan{}
	}
	d := findDomain(cfg, domain)
	if d == nil {
		return Plan{} // not one of our domains
	}
	r := resolver{cfg: cfg, secret: srsSecret, seen: map[string]bool{}}
	// local keeps its original case here: an incoming SRS bounce address
	// carries a case-sensitive base64 hash that must not be folded.
	r.resolve(local, domain, 0)
	p := r.plan
	p.Found = len(p.Local) > 0 || len(p.Remote) > 0
	return p
}

type resolver struct {
	cfg    *config.Config
	secret string
	seen   map[string]bool
	plan   Plan
}

// resolve expands one address into the plan. domain is assumed already
// lowercased; local is lowercased by the caller.
func (r *resolver) resolve(local, domain string, depth int) {
	if depth > maxDepth {
		return
	}
	addr := local + "@" + domain
	key := strings.ToLower(addr)
	if r.seen[key] {
		return // cycle or duplicate fan-in
	}
	r.seen[key] = true

	d := findDomain(r.cfg, domain)
	if d == nil {
		// The target is off-server: a forward.
		r.plan.Remote = append(r.plan.Remote, addr)
		return
	}

	// A real mailbox (virtual user or the domain's system account).
	if mb, ok := storage.Resolve(r.cfg, addr); ok {
		u := findUser(r.cfg, addr)
		if u == nil || u.KeepsLocalCopy() || len(u.ForwardTo) == 0 {
			r.plan.Local = append(r.plan.Local, Local{Mailbox: mb, Filters: filtersOf(u)})
		}
		if u != nil {
			for _, t := range u.ForwardTo {
				r.target(t, domain, depth+1)
			}
		}
		return
	}

	// An alias (possibly a distribution list, possibly to the outside).
	if targets := d.Aliases[strings.ToLower(local)]; len(targets) > 0 {
		for _, t := range targets {
			r.target(t, domain, depth+1)
		}
		return
	}

	// A returning bounce to an address we rewrote with SRS: reverse it
	// and relay the bounce to the original sender.
	if r.secret != "" && srs.IsSRS(local) {
		if orig, ok := srs.Reverse(r.secret, addr); ok {
			r.plan.Remote = append(r.plan.Remote, orig)
		}
		return
	}

	// Nothing matched: the domain's catch-all, if any, takes it.
	if len(d.CatchAll) > 0 {
		for _, t := range d.CatchAll {
			r.target(t, domain, depth+1)
		}
	}
}

// target resolves an alias/forward/catch-all target string. A bare local
// part (no '@') is taken to be in the same domain as the address that
// referenced it.
func (r *resolver) target(t, sameDomain string, depth int) {
	t = strings.TrimSpace(t)
	if t == "" {
		return
	}
	local, domain, ok := storage.Split(t)
	if !ok {
		// No '@': a local part in the referencing domain.
		local, domain = strings.ToLower(t), sameDomain
	} else {
		local = strings.ToLower(local)
	}
	r.resolve(local, domain, depth)
}

func findDomain(cfg *config.Config, name string) *config.Domain {
	for i := range cfg.Domains {
		if cfg.Domains[i].Name == name {
			return &cfg.Domains[i]
		}
	}
	return nil
}

func findUser(cfg *config.Config, email string) *config.User {
	for i := range cfg.Users {
		if strings.EqualFold(cfg.Users[i].Email, email) {
			return &cfg.Users[i]
		}
	}
	return nil
}

func filtersOf(u *config.User) []filter.Rule {
	if u == nil {
		return nil
	}
	return u.Filters
}
