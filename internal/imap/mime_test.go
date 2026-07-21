package imap

import (
	"fmt"
	"io"
	"strconv"
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

// A part that claims multipart but cannot be dissected must never be
// rendered as a multipart leaf — that displays as an empty message.
// It falls back to a text part so the content stays visible.
func TestUnparsableMultipartFallsBackToText(t *testing.T) {
	msg := "Content-Type: multipart/alternative; boundary=\"AAA\"\r\n\r\n" +
		"--BBB\r\nContent-Type: text/html\r\n\r\n<p>ciao</p>\r\n--BBB--\r\n"
	root := parseMessage([]byte(msg))
	s := structure(root, true)
	if strings.Contains(s, `"MULTIPART"`) {
		t.Errorf("unparsable multipart still rendered as a multipart leaf:\n%s", s)
	}
	if !strings.Contains(s, `"TEXT"`) {
		t.Errorf("fallback should be a text part:\n%s", s)
	}
	// The raw body is still fetchable, not empty.
	if got := resolveSection(root, "1"); !strings.Contains(got, "ciao") {
		t.Errorf("BODY[1] lost the content:\n%s", got)
	}
}

// Clients fetch a large body part in chunks with BODY[section]<off.len>.
// verta returned empty for the partial form, so any message with a
// sizable HTML part (a newsletter) displayed blank while small messages
// fetched whole worked. Reproduce the partial fetch end to end.
func TestPartialBodyFetch(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	// A message whose HTML part is bigger than one client chunk.
	html := "<html><body>" + strings.Repeat("<p>riga di newsletter</p>", 4000) + "</body></html>"
	msg := "From: news@brand.com\r\nSubject: grande\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"B\"\r\n\r\n" +
		"--B\r\nContent-Type: text/plain\r\n\r\ntesto\r\n" +
		"--B\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + html + "\r\n--B--\r\n"
	appendAndSelect(t, c, msg)

	// The whole HTML part, for reference.
	full := bodyLiteral(t, c, "FETCH 1 (BODY.PEEK[2])")
	if len(full) < 90000 {
		t.Fatalf("HTML part unexpectedly small: %d bytes", len(full))
	}

	// Fetch it in 16 KB chunks the way a client does, and reassemble.
	var got strings.Builder
	const chunk = 16384
	for off := 0; off < len(full); off += chunk {
		part := bodyLiteral(t, c, fmt.Sprintf("FETCH 1 (BODY.PEEK[2]<%d.%d>)", off, chunk))
		if part == "" {
			t.Fatalf("partial BODY[2]<%d.%d> returned empty", off, chunk)
		}
		got.WriteString(part)
	}
	if got.String() != full {
		t.Errorf("chunked fetch did not reassemble the part: got %d bytes, want %d",
			got.Len(), len(full))
	}
}

// bodyLiteral runs a FETCH expected to return one literal and returns
// exactly the literal's bytes, honoring the {n} count.
func bodyLiteral(t *testing.T, c *client, cmd string) string {
	t.Helper()
	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s %s\r\n", tag, cmd)
	for {
		line := c.readLine()
		if i := strings.LastIndex(line, "{"); i >= 0 && strings.HasSuffix(line, "}") {
			n, _ := strconv.Atoi(line[i+1 : len(line)-1])
			buf := make([]byte, n)
			if _, err := io.ReadFull(c.r, buf); err != nil {
				t.Fatalf("reading literal: %v", err)
			}
			// consume through the tagged completion
			for {
				if l := c.readLine(); strings.HasPrefix(l, tag+" ") {
					break
				}
			}
			return string(buf)
		}
		if strings.HasPrefix(line, tag+" ") {
			return ""
		}
	}
}
