package imap

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A multipart/alternative message — the shape Thunderbird composes for
// a plain message (text + HTML) — must produce a proper multipart
// BODYSTRUCTURE and let the client fetch each part on its own. Before
// this, verta advertised a malformed single-part structure claiming
// type MULTIPART, so Thunderbird could not find the text and showed the
// message empty.
func TestMultipartBodyStructureAndParts(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	text := "questo e il testo"
	html := "<p>questo e l'html</p>"
	msg := "From: me@example.com\r\nTo: you@example.com\r\nSubject: multipart\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"BOUND\"\r\n\r\n" +
		"--BOUND\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + text + "\r\n" +
		"--BOUND\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html + "\r\n" +
		"--BOUND--\r\n"

	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s APPEND INBOX {%d}\r\n", tag, len(msg))
	if line := c.readLine(); !strings.HasPrefix(line, "+") {
		t.Fatalf("APPEND continuation: %q", line)
	}
	fmt.Fprint(c.conn, msg+"\r\n")
	for {
		if line := c.readLine(); strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	c.ok("SELECT INBOX")

	// BODYSTRUCTURE must be a two-part multipart/alternative.
	bs := strings.Join(c.ok("FETCH 1 (BODYSTRUCTURE)"), "\n")
	t.Logf("BODYSTRUCTURE: %s", bs)
	if !strings.Contains(bs, `"ALTERNATIVE"`) {
		t.Errorf("BODYSTRUCTURE is not multipart/alternative:\n%s", bs)
	}
	if !strings.Contains(bs, `"TEXT" "PLAIN"`) || !strings.Contains(bs, `"TEXT" "HTML"`) {
		t.Errorf("BODYSTRUCTURE missing the two leaf parts:\n%s", bs)
	}
	// A single-part structure would open with the type: catch the
	// regression where a multipart was rendered as one leaf.
	if strings.HasPrefix(strings.TrimSpace(afterFetch(bs)), `("MULTIPART"`) {
		t.Errorf("multipart rendered as a single leaf:\n%s", bs)
	}

	// The client fetches each part on its own; each must return exactly
	// its content, not the whole body.
	part1 := strings.Join(c.ok("FETCH 1 (BODY.PEEK[1])"), "\n")
	if !strings.Contains(part1, text) || strings.Contains(part1, html) {
		t.Errorf("BODY[1] is not just the text part:\n%s", part1)
	}
	part2 := strings.Join(c.ok("FETCH 1 (BODY.PEEK[2])"), "\n")
	if !strings.Contains(part2, html) || strings.Contains(part2, text) {
		t.Errorf("BODY[2] is not just the html part:\n%s", part2)
	}

	// BODY[1.MIME] is the part's own header.
	mimeHdr := strings.Join(c.ok("FETCH 1 (BODY.PEEK[1.MIME])"), "\n")
	if !strings.Contains(strings.ToLower(mimeHdr), "text/plain") {
		t.Errorf("BODY[1.MIME] missing the part header:\n%s", mimeHdr)
	}
}

// A plain single-part message still fetches BODY[1] as its body and
// reports a text/plain BODYSTRUCTURE.
func TestSinglePartStillWorks(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	body := "solo testo semplice"
	msg := "From: me@example.com\r\nSubject: semplice\r\n\r\n" + body + "\r\n"
	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s APPEND INBOX {%d}\r\n", tag, len(msg))
	c.readLine()
	fmt.Fprint(c.conn, msg+"\r\n")
	for {
		if line := c.readLine(); strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	c.ok("SELECT INBOX")

	bs := strings.Join(c.ok("FETCH 1 (BODYSTRUCTURE)"), "\n")
	if !strings.Contains(bs, `"TEXT" "PLAIN"`) {
		t.Errorf("single-part BODYSTRUCTURE wrong:\n%s", bs)
	}
	part1 := strings.Join(c.ok("FETCH 1 (BODY.PEEK[1])"), "\n")
	if !strings.Contains(part1, body) {
		t.Errorf("BODY[1] of a single-part message should be its body:\n%s", part1)
	}
}

// afterFetch returns the part of a FETCH response after "BODYSTRUCTURE ".
func afterFetch(s string) string {
	if i := strings.Index(s, "BODYSTRUCTURE "); i >= 0 {
		return s[i+len("BODYSTRUCTURE "):]
	}
	return s
}
