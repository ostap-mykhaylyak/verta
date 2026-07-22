// Package srs implements the Sender Rewriting Scheme (SRS0) used when
// verta forwards mail to another provider.
//
// The problem it solves: when example.com forwards a message onward, the
// message keeps its original From (say news@brand.com) but is now sent
// from verta's IP. The receiving side checks SPF for brand.com, which
// does not list verta, and the forward fails SPF/DMARC — landing in spam
// or bouncing, and dragging verta's reputation down.
//
// SRS rewrites the *envelope* sender (MAIL FROM, i.e. Return-Path) to an
// address at the forwarding domain, so SPF is evaluated against a domain
// verta is authorised to send for:
//
//	news@brand.com  ->  SRS0=hash=tt=brand.com=news@example.com
//
// A bounce comes back to that address; verta is the MX for example.com,
// decodes it, verifies the HMAC and the timestamp, and relays the bounce
// to the original sender. The hash stops an open backscatter relay: only
// addresses verta itself signed are ever reversed.
package srs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"
)

// tsAlphabet is the SRS base32 timestamp alphabet (RFC 4648).
const tsAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// tsMod is the timestamp precision: two base32 chars = 1024 days.
const tsMod = int64(len(tsAlphabet)) * int64(len(tsAlphabet))

// maxAgeDays is how long a rewritten address stays valid for a returning
// bounce. A day of future skew is tolerated for clock differences.
const maxAgeDays = 21

// IsSRS reports whether a local part looks like an address this package
// produced (an SRS0 forward address).
func IsSRS(localPart string) bool {
	return strings.HasPrefix(strings.ToUpper(localPart), "SRS0=")
}

// Forward rewrites sender into an SRS0 address at forwardDomain, so a
// message verta forwards passes SPF at the destination. An empty sender
// (a bounce's null return-path) is returned unchanged: bounces must keep
// the null sender. A sender that cannot be parsed is also left as is.
func Forward(secret, forwardDomain, sender string) string {
	if sender == "" {
		return ""
	}
	local, domain, ok := split(sender)
	if !ok {
		return sender
	}
	tt := timestamp(time.Now())
	h := sign(secret, tt, domain, local)
	return fmt.Sprintf("SRS0=%s=%s=%s=%s@%s", h, tt, domain, local, forwardDomain)
}

// Reverse recovers the original sender from an SRS0 address, verifying
// the HMAC and the timestamp. ok is false for anything not signed by
// this secret or older than the validity window — which is exactly what
// keeps the reverse path from becoming an open backscatter relay.
func Reverse(secret, srsAddress string) (sender string, ok bool) {
	local, _, has := split(srsAddress)
	if !has || !IsSRS(local) {
		return "", false
	}
	// SRS0=<hash>=<tt>=<domain>=<origlocal>. The original local part may
	// itself contain '=', so bound the split to five fields.
	parts := strings.SplitN(local, "=", 5)
	if len(parts) != 5 {
		return "", false
	}
	h, tt, domain, origLocal := parts[1], parts[2], parts[3], parts[4]
	if !hmac.Equal([]byte(sign(secret, tt, domain, origLocal)), []byte(h)) {
		return "", false
	}
	if !timestampValid(tt, time.Now()) {
		return "", false
	}
	return origLocal + "@" + domain, true
}

// sign is the truncated HMAC-SHA1 over the timestamp and original
// address, the tamper check embedded in the rewritten local part.
func sign(secret, tt, domain, local string) string {
	mac := hmac.New(sha1.New, []byte(secret))
	io.WriteString(mac, strings.ToLower(tt+domain+local))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))[:4]
}

// timestamp encodes today (days since the Unix epoch, mod 1024) as two
// base32 characters.
func timestamp(now time.Time) string {
	days := now.Unix() / 86400 % tsMod
	return string([]byte{tsAlphabet[(days/32)&31], tsAlphabet[days&31]})
}

// timestampValid reports whether tt is within the acceptance window of
// now, accounting for the modular wrap of the two-character field.
func timestampValid(tt string, now time.Time) bool {
	if len(tt) != 2 {
		return false
	}
	hi := strings.IndexByte(tsAlphabet, upper(tt[0]))
	lo := strings.IndexByte(tsAlphabet, upper(tt[1]))
	if hi < 0 || lo < 0 {
		return false
	}
	then := int64(hi*32 + lo)
	nowDays := now.Unix() / 86400 % tsMod
	// Forward modular distance from then to now.
	age := (nowDays - then + tsMod) % tsMod
	// Valid if at most maxAgeDays old, or up to one day in the future.
	return age <= maxAgeDays || age >= tsMod-1
}

func upper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 32
	}
	return b
}

// split separates local part and lowercased domain of an address.
func split(addr string) (local, domain string, ok bool) {
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return "", "", false
	}
	return addr[:at], strings.ToLower(addr[at+1:]), true
}
