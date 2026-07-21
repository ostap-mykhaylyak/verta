package imap

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// appendAndSelect appends msg to INBOX and selects it. Returns the client.
func appendAndSelect(t *testing.T, c *client, msg string) {
	t.Helper()
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
}

// A newsletter's HTML part is almost always quoted-printable or base64
// and the message may nest multipart/related (inline images) inside
// multipart/alternative. Reproduce the shape and check the HTML part
// is found and returned intact.
func TestNewsletterHTMLFetch(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	htmlQP := "<html><body><h1>Newsletter</h1><p>Ciao =E2=9C=93 offerta=\r\n speciale</p></body></html>"
	msg := "From: news@brand.com\r\nTo: you@example.com\r\nSubject: Newsletter\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"ALT\"\r\n\r\n" +
		"--ALT\r\nContent-Type: text/plain; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n\r\nversione testo\r\n" +
		"--ALT\r\nContent-Type: multipart/related; boundary=\"REL\"\r\n\r\n" +
		"--REL\r\nContent-Type: text/html; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n\r\n" + htmlQP + "\r\n" +
		"--REL\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n" +
		"Content-ID: <logo>\r\n\r\niVBORw0KGgo=\r\n" +
		"--REL--\r\n" +
		"--ALT--\r\n"

	appendAndSelect(t, c, msg)

	bs := strings.Join(c.ok("FETCH 1 (BODYSTRUCTURE)"), "\n")
	t.Logf("BODYSTRUCTURE: %s", bs)

	// The HTML lives at part 2.1 (inside the related part).
	html := strings.Join(c.ok("FETCH 1 (BODY.PEEK[2.1])"), "\n")
	t.Logf("BODY[2.1]: %s", html)
	if !strings.Contains(html, "Newsletter") || !strings.Contains(html, "=E2=9C=93") {
		t.Errorf("HTML part not returned intact at BODY[2.1]:\n%s", html)
	}
	// The structure must report the HTML part's encoding, or the client
	// shows the raw quoted-printable (or nothing).
	if !strings.Contains(strings.ToUpper(bs), "QUOTED-PRINTABLE") {
		t.Errorf("BODYSTRUCTURE does not report the HTML encoding:\n%s", bs)
	}
	if !strings.Contains(strings.ToUpper(bs), `"HTML"`) {
		t.Errorf("BODYSTRUCTURE does not describe the HTML part:\n%s", bs)
	}
}

// A single-part text/html message (a simple newsletter with no plain
// alternative) must fetch its body as BODY[1].
func TestSinglePartHTML(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	html := "<html><body><p>solo html</p></body></html>"
	msg := "From: n@b.com\r\nSubject: html\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" + html + "\r\n"
	appendAndSelect(t, c, msg)

	bs := strings.Join(c.ok("FETCH 1 (BODYSTRUCTURE)"), "\n")
	if !strings.Contains(strings.ToUpper(bs), `"TEXT" "HTML"`) {
		t.Errorf("single-part HTML BODYSTRUCTURE wrong:\n%s", bs)
	}
	body := strings.Join(c.ok("FETCH 1 (BODY.PEEK[1])"), "\n")
	if !strings.Contains(body, "solo html") {
		t.Errorf("BODY[1] of a single-part HTML message is empty:\n%s", body)
	}
}
