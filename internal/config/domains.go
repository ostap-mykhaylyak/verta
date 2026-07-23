package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ostap-mykhaylyak/verta/internal/quota"
	"gopkg.in/yaml.v3"
)

// DomainFile is one file under the domains directory: a hosted domain
// together with its mailboxes.
//
// Domains live outside the main configuration on purpose. Adding a
// customer, changing one mailbox password or handing a single domain
// to a provisioning script must not mean rewriting the file that also
// holds the listeners and the TLS settings — and a syntax error in one
// customer's file must not take the whole server down with it.
type DomainFile struct {
	// Name is the domain, and must match the file name.
	Name string `yaml:"name"`
	// DKIMSelector names the signing key; empty means "default".
	DKIMSelector string `yaml:"dkim_selector"`
	// Storage describes where this domain's mailboxes live.
	Storage Storage `yaml:"storage"`
	// Users are the virtual mailboxes of this domain.
	Users []User `yaml:"users"`
	// Aliases map a local part to one or more targets (local mailboxes
	// or external addresses).
	Aliases map[string]Targets `yaml:"aliases"`
	// CatchAll receives every address in the domain that matches no
	// mailbox and no alias. Empty rejects unknown addresses.
	CatchAll Targets `yaml:"catch_all"`
	// Outbound is this domain's outbound policy (egress IP, rate, pacing).
	Outbound OutboundPolicy `yaml:"outbound"`
	// Quota is the shared disk limit for all the domain's mailboxes
	// ("10G", "2000M"; empty = unlimited).
	Quota string `yaml:"quota"`

	// path is where the file was read from, for error messages.
	path string
}

// loadDomains reads every *.yaml file in dir and merges the result
// into the configuration. A file that fails to parse is reported and
// skipped: one broken domain must not stop the other domains from
// being served, so the error becomes a warning and the domain simply
// does not exist until it is fixed.
func (c *Config) loadDomains(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			c.warnf("domains directory %s does not exist: no domain is served", dir)
			return nil
		}
		return fmt.Errorf("domains directory %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		// .yaml only, so an editor backup or a .example file left in
		// the directory is ignored rather than half-loaded.
		if !strings.HasSuffix(n, ".yaml") || strings.HasPrefix(n, ".") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)

	seen := map[string]bool{}
	for _, n := range names {
		path := filepath.Join(dir, n)
		df, err := loadDomainFile(path)
		if err != nil {
			c.warnf("%v", err)
			continue
		}
		if seen[df.Name] {
			c.warnf("domain %s is defined more than once, %s ignored", df.Name, path)
			continue
		}
		seen[df.Name] = true

		domainQuota, err := quota.ParseSize(df.Quota)
		if err != nil {
			c.warnf("domain %s: invalid quota %q, treated as unlimited", df.Name, df.Quota)
		}
		// A malformed mailbox quota must be visible, not silently zero.
		for _, u := range df.Users {
			if _, err := quota.ParseSize(u.Quota); err != nil {
				c.warnf("mailbox %s: invalid quota %q, treated as unlimited", u.Email, u.Quota)
			}
		}

		c.Domains = append(c.Domains, Domain{
			Name:         df.Name,
			Storage:      df.Storage,
			DKIMSelector: df.DKIMSelector,
			Aliases:      normalizeAliases(df.Aliases),
			CatchAll:     df.CatchAll,
			Outbound:     df.Outbound,
			QuotaBytes:   domainQuota,
		})
		c.Users = append(c.Users, df.Users...)
	}
	return nil
}

// loadDomainFile reads and validates one domain file.
func loadDomainFile(path string) (*DomainFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()

	var df DomainFile
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&df); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	df.path = path

	// The file name is the source of truth for the domain: it is what
	// an operator greps for, and what a provisioning script writes.
	base := strings.TrimSuffix(filepath.Base(path), ".yaml")
	base = normalizeHost(base)
	df.Name = normalizeHost(df.Name)
	switch {
	case df.Name == "":
		df.Name = base
	case df.Name != base:
		return nil, fmt.Errorf("%s: declares domain %q but the file is named %q.yaml; rename the file or fix the name",
			path, df.Name, base)
	}
	if df.Name == "" {
		return nil, fmt.Errorf("%s: the file name does not give a domain name", path)
	}
	if !strings.Contains(df.Name, ".") {
		return nil, fmt.Errorf("%s: %q is not a valid domain (no dot)", path, df.Name)
	}
	return &df, nil
}

// WriteDomainFile writes a domain definition to dir, for `verta --init`
// and for provisioning tools.
func WriteDomainFile(dir string, df DomainFile) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, df.Name+".yaml")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	b, err := yaml.Marshal(df)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o640)
}
