package storage

import (
	"testing"

	"github.com/ostap-mykhaylyak/verta/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Domains: []config.Domain{
			{Name: "example.com"},
			{Name: "ostap.dev", Storage: config.Storage{
				Type: config.StorageSystemUser, User: "ostap",
				Home: "/home/ostap", Maildir: "{home}/mail",
			}},
		},
		Users: []config.User{
			{Email: "admin@example.com", Maildir: "/var/mail/example.com/admin"},
		},
	}
}

func TestResolveVirtual(t *testing.T) {
	mb, ok := Resolve(testConfig(), "Admin@Example.COM")
	if !ok {
		t.Fatal("want resolved")
	}
	if mb.Dir != "/var/mail/example.com/admin" || mb.Email != "admin@example.com" {
		t.Errorf("mailbox = %+v", mb)
	}
}

func TestResolveSystemUser(t *testing.T) {
	mb, ok := Resolve(testConfig(), "ostap@ostap.dev")
	if !ok {
		t.Fatal("want resolved")
	}
	if mb.Dir != "/home/ostap/mail" {
		t.Errorf("dir = %q", mb.Dir)
	}
	if _, ok := Resolve(testConfig(), "other@ostap.dev"); ok {
		t.Error("system_user domain must only expose its bound account")
	}
}

func TestResolveUnknown(t *testing.T) {
	if _, ok := Resolve(testConfig(), "nobody@example.com"); ok {
		t.Error("unknown virtual user must not resolve")
	}
	if _, ok := Resolve(testConfig(), "a@elsewhere.org"); ok {
		t.Error("foreign domain must not resolve")
	}
	if _, ok := Resolve(testConfig(), "not-an-address"); ok {
		t.Error("malformed address must not resolve")
	}
}

// Several mailboxes can live under one system account: each resolves to
// its own Maildir (with {home} expanded) while staying owned by the
// account. The bare account address is no longer valid once users exist.
func TestResolveSystemUserMultipleMailboxes(t *testing.T) {
	cfg := &config.Config{
		Domains: []config.Domain{
			{Name: "ostap.dev", Storage: config.Storage{
				Type: config.StorageSystemUser, User: "ostap", Home: "/home/ostap",
				Maildir: "{home}/mail",
			}},
		},
		Users: []config.User{
			{Email: "mario@ostap.dev", Maildir: "{home}/mail/mario"},
			{Email: "antonio@ostap.dev", Maildir: "/home/ostap/mail/antonio"},
		},
	}
	mario, ok := Resolve(cfg, "mario@ostap.dev")
	if !ok || mario.Dir != "/home/ostap/mail/mario" {
		t.Errorf("mario = %+v, %v", mario, ok)
	}
	antonio, ok := Resolve(cfg, "antonio@ostap.dev")
	if !ok || antonio.Dir != "/home/ostap/mail/antonio" {
		t.Errorf("antonio = %+v, %v", antonio, ok)
	}
	// With users listed, the bare account address is not a mailbox.
	if _, ok := Resolve(cfg, "ostap@ostap.dev"); ok {
		t.Error("bare account must not resolve once users are listed")
	}
}
