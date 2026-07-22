package config

import "gopkg.in/yaml.v3"

// Targets is one or more addresses. In YAML it accepts either a bare
// scalar or a list, so both of these are valid:
//
//	info: mario@example.com
//	sales: [mario@example.com, lucia@example.com]
type Targets []string

// UnmarshalYAML accepts a scalar or a sequence.
func (t *Targets) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		*t = Targets{s}
		return nil
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return err
	}
	*t = Targets(list)
	return nil
}

// Forwarding holds the settings that apply to every forward and alias
// that points off-server.
type Forwarding struct {
	// SRSSecret keys the Sender Rewriting Scheme. It must stay stable:
	// a bounce may return weeks later and is only accepted if it still
	// verifies. `verta --init` generates one. Empty disables SRS, and
	// forwards go out with the original envelope sender (simpler, but
	// they can fail SPF at the destination).
	SRSSecret string `yaml:"srs_secret"`
}

// normalizeAliases lowercases the alias keys (local parts are matched
// case-insensitively) and drops an empty map to nil.
func normalizeAliases(in map[string]Targets) map[string]Targets {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]Targets, len(in))
	for k, v := range in {
		out[toLower(k)] = v
	}
	return out
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// KeepsLocalCopy reports whether a forwarding mailbox also stores the
// message locally. The default is yes: a misconfigured forward must not
// silently lose mail. Set `keep_local: false` for forward-only.
func (u User) KeepsLocalCopy() bool {
	return u.KeepLocal == nil || *u.KeepLocal
}
