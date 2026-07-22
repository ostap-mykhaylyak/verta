package routing

import (
	"sort"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/verta/internal/config"
	"github.com/ostap-mykhaylyak/verta/internal/filter"
	"github.com/ostap-mykhaylyak/verta/internal/srs"
)

const secret = "routing-test-secret"

func testCfg() *config.Config {
	no := false
	return &config.Config{
		Domains: []config.Domain{{
			Name: "example.com",
			Aliases: map[string]config.Targets{
				"info":    {"mario@example.com"},
				"sales":   {"mario@example.com", "lucia@example.com"},
				"support": {"ext@partner.com"},
				"loopa":   {"loopb@example.com"},
				"loopb":   {"loopa@example.com"},
			},
			CatchAll: config.Targets{"lucia@example.com"},
		}},
		Users: []config.User{
			{Email: "mario@example.com", Maildir: "/m/mario",
				ForwardTo: config.Targets{"backup@gmail.com"},
				Filters:   []filter.Rule{{From: "boss@", Flagged: true}}},
			{Email: "lucia@example.com", Maildir: "/m/lucia"},
			{Email: "onlyfwd@example.com", Maildir: "/m/onlyfwd",
				ForwardTo: config.Targets{"x@out.com"}, KeepLocal: &no},
		},
	}
}

func locals(p Plan) []string {
	var out []string
	for _, l := range p.Local {
		out = append(out, l.Mailbox.Email)
	}
	sort.Strings(out)
	return out
}

func eq(t *testing.T, got, want []string, what string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestDirectUser(t *testing.T) {
	p := Resolve(testCfg(), secret, "lucia@example.com")
	eq(t, locals(p), []string{"lucia@example.com"}, "local")
	if len(p.Remote) != 0 || !p.Found {
		t.Errorf("unexpected remote/found: %+v", p)
	}
}

func TestAliasToUser(t *testing.T) {
	p := Resolve(testCfg(), secret, "info@example.com")
	// info -> mario, who also forwards.
	eq(t, locals(p), []string{"mario@example.com"}, "local")
	eq(t, p.Remote, []string{"backup@gmail.com"}, "remote")
}

func TestDistributionList(t *testing.T) {
	p := Resolve(testCfg(), secret, "sales@example.com")
	eq(t, locals(p), []string{"lucia@example.com", "mario@example.com"}, "local")
	eq(t, p.Remote, []string{"backup@gmail.com"}, "remote") // mario forwards
}

func TestAliasToExternalIsForward(t *testing.T) {
	p := Resolve(testCfg(), secret, "support@example.com")
	if len(p.Local) != 0 {
		t.Errorf("external alias must not deliver locally: %+v", locals(p))
	}
	eq(t, p.Remote, []string{"ext@partner.com"}, "remote")
}

func TestForwardKeepsLocalByDefault(t *testing.T) {
	p := Resolve(testCfg(), secret, "mario@example.com")
	eq(t, locals(p), []string{"mario@example.com"}, "local")
	eq(t, p.Remote, []string{"backup@gmail.com"}, "remote")
	// The mailbox carries its filters through to delivery.
	if len(p.Local[0].Filters) != 1 {
		t.Errorf("filters not attached: %+v", p.Local[0].Filters)
	}
}

func TestForwardOnly(t *testing.T) {
	p := Resolve(testCfg(), secret, "onlyfwd@example.com")
	if len(p.Local) != 0 {
		t.Errorf("keep_local:false must not store locally: %+v", locals(p))
	}
	eq(t, p.Remote, []string{"x@out.com"}, "remote")
}

func TestCatchAll(t *testing.T) {
	p := Resolve(testCfg(), secret, "chiunque@example.com")
	eq(t, locals(p), []string{"lucia@example.com"}, "local")
}

func TestUnknownWithoutCatchAll(t *testing.T) {
	cfg := testCfg()
	cfg.Domains[0].CatchAll = nil
	p := Resolve(cfg, secret, "nobody@example.com")
	if p.Found {
		t.Errorf("unknown address without catch-all must not be found: %+v", p)
	}
}

func TestForeignDomainNotFound(t *testing.T) {
	if Resolve(testCfg(), secret, "x@notours.com").Found {
		t.Error("a foreign domain must not resolve")
	}
}

func TestAliasLoopTerminates(t *testing.T) {
	// loopa -> loopb -> loopa: must stop, not hang or fan out.
	p := Resolve(testCfg(), secret, "loopa@example.com")
	if p.Found || len(p.Local) != 0 || len(p.Remote) != 0 {
		t.Errorf("a cyclic alias must resolve to nothing: %+v", p)
	}
}

// A domain with no mailboxes and a catch-all pointing at an external
// address forwards *everything* it receives: the "@studenti.scuola.it ->
// one Gmail" case. Any local part resolves to the same remote.
func TestCatchAllToExternalForwardsEverything(t *testing.T) {
	cfg := &config.Config{
		Domains: []config.Domain{{
			Name:     "studenti.scuola.it",
			CatchAll: config.Targets{"classe3b@gmail.com"},
		}},
	}
	for _, addr := range []string{"mario.rossi@studenti.scuola.it", "chiunque@studenti.scuola.it"} {
		p := Resolve(cfg, secret, addr)
		if len(p.Local) != 0 {
			t.Errorf("%s must not deliver locally: %v", addr, locals(p))
		}
		eq(t, p.Remote, []string{"classe3b@gmail.com"}, "remote for "+addr)
	}
}

func TestSRSBounceReturns(t *testing.T) {
	bounce := srs.Forward(secret, "example.com", "news@brand.com")
	p := Resolve(testCfg(), secret, bounce)
	eq(t, p.Remote, []string{"news@brand.com"}, "remote")
	if len(p.Local) != 0 {
		t.Errorf("an SRS bounce must not land locally: %+v", locals(p))
	}
}
