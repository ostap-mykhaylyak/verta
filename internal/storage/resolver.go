// Package storage resolves recipient addresses to their mailbox on
// disk, across the two storage models: system_user domains (a real
// Linux account with a Maildir in its home) and virtual mailboxes
// (the users list in the configuration).
package storage

import (
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/ostap-mykhaylyak/verta/internal/config"
)

// Mailbox is a deliverable local mailbox.
type Mailbox struct {
	Email string
	// Dir is the Maildir root.
	Dir string
	// UID/GID own the mailbox for system users; -1 means no chown
	// (virtual mailboxes, non-Linux systems).
	UID, GID int
}

// Split separates an address into local part and lowercased domain.
// ok is false when the address has no usable form.
func Split(email string) (local, domain string, ok bool) {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", "", false
	}
	return email[:at], strings.ToLower(email[at+1:]), true
}

// Resolve maps a recipient address to its mailbox under cfg. ok is
// false when the address is not a deliverable local mailbox — the
// caller distinguishes "unknown user" from "not our domain" via
// cfg.HasDomain.
func Resolve(cfg *config.Config, email string) (Mailbox, bool) {
	local, domain, ok := Split(email)
	if !ok {
		return Mailbox{}, false
	}
	// The local part is matched case-insensitively: mailbox names are
	// ASCII account names in both storage models.
	local = strings.ToLower(local)
	addr := local + "@" + domain

	for _, d := range cfg.Domains {
		if d.Name != domain {
			continue
		}
		if d.Storage.Type == config.StorageSystemUser {
			// Several virtual mailboxes may live under one Linux account:
			// each is listed in users with its own Maildir, but every file
			// is owned by the account's UID/GID. A "{home}" in the maildir
			// expands to the account home.
			hasUsers := false
			for _, u := range cfg.Users {
				if u.Email == addr {
					mb := Mailbox{Email: addr, Dir: d.Storage.ExpandHome(u.Maildir), UID: -1, GID: -1}
					fillOwner(&mb, d.Storage.User)
					return mb, true
				}
				if _, dom, ok := Split(u.Email); ok && dom == domain {
					hasUsers = true
				}
			}
			// With no users listed the domain is the single bound account
			// (the original system_user model, ostap@ostap.dev).
			if !hasUsers && local == d.Storage.User {
				mb := Mailbox{Email: addr, Dir: d.Storage.MaildirPath(), UID: -1, GID: -1}
				fillOwner(&mb, d.Storage.User)
				return mb, true
			}
			return Mailbox{}, false
		}
		for _, u := range cfg.Users {
			if u.Email == addr {
				return Mailbox{Email: addr, Dir: u.Maildir, UID: -1, GID: -1}, true
			}
		}
		return Mailbox{}, false
	}
	return Mailbox{}, false
}

// fillOwner resolves the numeric UID/GID of a Linux account. Failures
// leave -1: delivery still works, ownership is just not changed.
func fillOwner(mb *Mailbox, name string) {
	if runtime.GOOS != "linux" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	if uid, err := strconv.Atoi(u.Uid); err == nil {
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			mb.UID, mb.GID = uid, gid
		}
	}
}
