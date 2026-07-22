package config

import "testing"

// The domain-file forwarding features must parse under KnownFields(true):
// aliases (scalar and list), catch_all, and per-user forward_to /
// keep_local / filters.
func TestDomainForwardingFeaturesParse(t *testing.T) {
	dom := `name: example.com
aliases:
  info: admin@example.com
  sales: [admin@example.com, lucia@example.com]
catch_all: admin@example.com
users:
  - email: admin@example.com
    maildir: /var/mail/admin
    forward_to: [backup@gmail.com]
    keep_local: false
    filters:
      - from: "newsletter@"
        folder: Newsletters
        stop: true
`
	cfg, err := Load(write(t, minimal, map[string]string{"example.com": dom}))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Domains[0]
	if len(d.Aliases["info"]) != 1 || d.Aliases["info"][0] != "admin@example.com" {
		t.Errorf("alias info = %v", d.Aliases["info"])
	}
	if len(d.Aliases["sales"]) != 2 {
		t.Errorf("alias sales = %v", d.Aliases["sales"])
	}
	if len(d.CatchAll) != 1 || d.CatchAll[0] != "admin@example.com" {
		t.Errorf("catch_all = %v", d.CatchAll)
	}
	u := cfg.Users[0]
	if len(u.ForwardTo) != 1 || u.KeepsLocalCopy() {
		t.Errorf("forward_to/keep_local wrong: forward=%v keep=%v", u.ForwardTo, u.KeepsLocalCopy())
	}
	if len(u.Filters) != 1 || u.Filters[0].Folder != "Newsletters" || !u.Filters[0].Stop {
		t.Errorf("filters = %+v", u.Filters)
	}
}
