package config

import "strings"

// DomainQuota returns the shared disk limit for a domain in bytes
// (0 = unlimited).
func (c *Config) DomainQuota(domain string) int64 {
	for _, d := range c.Domains {
		if d.Name == domain {
			return d.QuotaBytes
		}
	}
	return 0
}

// UserQuota returns a mailbox's own disk limit in bytes (0 = unlimited).
func (c *Config) UserQuota(email string) int64 {
	for _, u := range c.Users {
		if strings.EqualFold(u.Email, email) {
			return u.QuotaBytes()
		}
	}
	return 0
}

// DomainMaildirs lists the Maildir root of every mailbox in a domain, so
// the shared-quota total can be summed across them.
func (c *Config) DomainMaildirs(domain string) []string {
	for _, d := range c.Domains {
		if d.Name == domain && d.Storage.Type == StorageSystemUser {
			// A system-user domain has a single account mailbox.
			return []string{d.Storage.MaildirPath()}
		}
	}
	var dirs []string
	for _, u := range c.Users {
		if at := strings.LastIndex(u.Email, "@"); at >= 0 &&
			strings.EqualFold(u.Email[at+1:], domain) {
			dirs = append(dirs, u.Maildir)
		}
	}
	return dirs
}
