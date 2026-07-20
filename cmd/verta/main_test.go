package main

import (
	"strings"
	"testing"
)

func TestNormalizeCommand(t *testing.T) {
	// Service verbs: bare accepted, --form rejected with a hint.
	for _, verb := range []string{"start", "stop", "reload", "restart"} {
		got, err := normalizeCommand(verb)
		if err != nil || got != verb {
			t.Errorf("normalizeCommand(%q) = %q, %v; want %q, nil", verb, got, err, verb)
		}
		if _, err := normalizeCommand("--" + verb); err == nil {
			t.Errorf("--%s must be rejected (service verbs take no --)", verb)
		} else if !strings.Contains(err.Error(), "no leading --") {
			t.Errorf("--%s error should explain the convention: %v", verb, err)
		}
	}

	// Flag commands: --form accepted and stripped, bare rejected.
	for _, name := range []string{
		"init", "purge", "status", "check-config", "version",
		"hash-password", "generate-dkim", "audit", "security-check", "container-check",
	} {
		got, err := normalizeCommand("--" + name)
		if err != nil || got != name {
			t.Errorf("normalizeCommand(--%s) = %q, %v; want %q, nil", name, got, err, name)
		}
		if _, err := normalizeCommand(name); err == nil {
			t.Errorf("bare %q must be rejected (everything but service verbs takes --)", name)
		} else if !strings.Contains(err.Error(), "leading --") {
			t.Errorf("bare %q error should explain the convention: %v", name, err)
		}
	}

	// Unknown commands are rejected in either form.
	for _, bad := range []string{"frobnicate", "--frobnicate", "-status", "start-now"} {
		if _, err := normalizeCommand(bad); err == nil {
			t.Errorf("normalizeCommand(%q) should fail", bad)
		}
	}
}

// Every command the switch handles must be classified by exactly one
// table, and every classified command must be handled — otherwise a
// command would either be unreachable or fall through to the
// unreachable default.
func TestCommandTablesAreDisjoint(t *testing.T) {
	for c := range serviceVerbs {
		if flagCommands[c] {
			t.Errorf("%q is in both serviceVerbs and flagCommands", c)
		}
	}
}
