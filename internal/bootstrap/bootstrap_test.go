package bootstrap

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// The mailbox location verta ships in the example domain file must be
// writable under the systemd unit verta ships. They were once
// inconsistent — the example put mailboxes in /var/mail while the unit
// mounted everything but /var/lib and /var/log read-only, so delivery
// and folder creation failed with "read-only file system". This test
// keeps the two in agreement.
func TestShippedMailboxIsWritableUnderShippedUnit(t *testing.T) {
	prot, rwPaths := unitSandbox(t, Unit)
	maildirs := exampleMaildirs(t, exampleDomain)
	if len(maildirs) == 0 {
		t.Fatal("the example domain file declares no maildir to check")
	}
	for _, m := range maildirs {
		if !writableUnder(m, prot, rwPaths) {
			t.Errorf("example maildir %q is not writable under ProtectSystem=%s (ReadWritePaths=%v): "+
				"delivery would fail with a read-only filesystem", m, prot, rwPaths)
		}
	}
}

// unitSandbox extracts the ProtectSystem mode and ReadWritePaths from a
// systemd unit.
func unitSandbox(t *testing.T, unit []byte) (protectSystem string, readWrite []string) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(unit))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "ProtectSystem="); ok {
			protectSystem = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "ReadWritePaths="); ok {
			readWrite = append(readWrite, strings.Fields(v)...)
		}
	}
	return protectSystem, readWrite
}

// exampleMaildirs returns the uncommented maildir paths in a domain
// file.
func exampleMaildirs(t *testing.T, domain []byte) []string {
	t.Helper()
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(domain))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "maildir:"); ok {
			out = append(out, strings.Trim(strings.TrimSpace(v), `"`))
		}
	}
	return out
}

// writableUnder models systemd's ProtectSystem: "full" keeps /usr,
// /boot, /efi and /etc read-only and leaves the rest writable; "strict"
// makes everything read-only except ReadWritePaths; unset/"false"
// leaves everything writable.
func writableUnder(path, protectSystem string, readWrite []string) bool {
	switch protectSystem {
	case "", "false", "no":
		return true
	case "full", "yes", "true":
		for _, ro := range []string{"/usr", "/boot", "/efi", "/etc"} {
			if path == ro || strings.HasPrefix(path, ro+"/") {
				return false
			}
		}
		return true
	case "strict":
		for _, rw := range readWrite {
			if path == rw || strings.HasPrefix(path, rw+"/") {
				return true
			}
		}
		return false
	default:
		// An unrecognized mode: treat as not writable so the test
		// surfaces it rather than passing silently.
		return false
	}
}
