// Package egress chooses the source IP and EHLO name for each outbound
// SMTP connection, rotating across a pool of addresses. A server with
// several public IPs — or several NAT'd addresses inside an LXD
// container — can then spread its outbound mail and build per-IP
// reputation, with three strategies:
//
//   - recipient_domain (default): the same destination domain always
//     leaves from the same IP (sticky by hash). Best for reputation and
//     warm-up — a receiver like Gmail sees one consistent IP.
//   - sender_domain: each hosted domain is pinned to its own IP, so the
//     reputation of one tenant does not spill onto another.
//   - round_robin: the next IP in sequence per message.
//
// Inside a container the world-facing address (Public: PTR, SPF, EHLO)
// differs from the address verta actually binds (Bind: the internal
// bridge IP the host SNATs to that public IP). On a plain host the two
// are the same and Bind can be left empty.
package egress

import (
	"hash/fnv"
	"strings"
	"sync/atomic"
)

// Selection strategies.
const (
	StrategyRecipientDomain = "recipient_domain"
	StrategySenderDomain    = "sender_domain"
	StrategyRoundRobin      = "round_robin"
)

// Address is one outbound source.
type Address struct {
	// Public is the address the world sees: its PTR, what belongs in the
	// domains' SPF, and (via HELO) the name it announces. Required.
	Public string
	// HELO is the EHLO name for this IP; it should resolve to Public and
	// match Public's reverse DNS. Empty falls back to the caller's
	// default hostname.
	HELO string
	// Bind is the local IP to bind the socket to. Empty (or equal to
	// Public) binds nothing special — the OS default. Set it to the
	// container's internal bridge IP that the host maps to Public.
	Bind string
	// Domains are the hosted sender domains routed to this IP under the
	// sender_domain strategy.
	Domains []string
}

// Source is the resolved choice for one connection.
type Source struct {
	// Bind is the local IP to bind ("" = OS default).
	Bind string
	// HELO is the EHLO name ("" = caller's default hostname).
	HELO string
}

// Pool selects a Source per outbound connection. A nil Pool means "no
// rotation configured": the caller uses its default source and hostname.
type Pool struct {
	addrs    []Address
	strategy string
	byDomain map[string]int // sender domain -> address index
	rr       atomic.Uint64
}

// New builds a Pool. An empty address list returns nil (rotation off).
func New(strategy string, addrs []Address) *Pool {
	if len(addrs) == 0 {
		return nil
	}
	if strategy == "" {
		strategy = StrategyRecipientDomain
	}
	p := &Pool{addrs: addrs, strategy: strategy, byDomain: map[string]int{}}
	for i, a := range addrs {
		for _, d := range a.Domains {
			p.byDomain[strings.ToLower(d)] = i
		}
	}
	return p
}

// ByAddress returns the source for a specific public IP in the pool,
// used when a domain or mailbox is pinned to one address. ok is false
// when the address is not in the pool.
func (p *Pool) ByAddress(public string) (Source, bool) {
	if p == nil {
		return Source{}, false
	}
	for _, a := range p.addrs {
		if a.Public == public {
			return a.source(), true
		}
	}
	return Source{}, false
}

func (a Address) source() Source {
	bind := a.Bind
	if bind == "" {
		bind = a.Public
	}
	return Source{Bind: bind, HELO: a.HELO}
}

// Select resolves the source for a message from `from` to `rcptDomain`.
func (p *Pool) Select(from, rcptDomain string) Source {
	if p == nil || len(p.addrs) == 0 {
		return Source{}
	}
	switch p.strategy {
	case StrategySenderDomain:
		dom := domainOf(from)
		if i, ok := p.byDomain[strings.ToLower(dom)]; ok {
			return p.addrs[i].source()
		}
		// A domain not explicitly mapped still gets a stable IP.
		return p.addrs[hashIndex(dom, len(p.addrs))].source()
	case StrategyRoundRobin:
		i := int(p.rr.Add(1)-1) % len(p.addrs)
		return p.addrs[i].source()
	default: // recipient_domain, sticky by hash
		return p.addrs[hashIndex(strings.ToLower(rcptDomain), len(p.addrs))].source()
	}
}

func hashIndex(s string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32() % uint32(n))
}

func domainOf(addr string) string {
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		return addr[at+1:]
	}
	return ""
}
