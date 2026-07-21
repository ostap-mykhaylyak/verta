package imap

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A fresh account must expose the standard folders, each carrying its
// RFC 6154 special-use attribute, so a mail client can file sent mail
// without the user creating anything. Missing folders (and an LSUB
// that echoed the wrong command name) left Thunderbird stuck on
// "copying to Sent".
func TestStandardFoldersAndSpecialUse(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	// CAPABILITY must advertise SPECIAL-USE.
	caps := strings.Join(c.ok("CAPABILITY"), " ")
	if !strings.Contains(caps, "SPECIAL-USE") {
		t.Errorf("CAPABILITY missing SPECIAL-USE:\n%s", caps)
	}

	// LIST shows the standard folders with their special-use flags.
	list := strings.Join(c.ok(`LIST "" "*"`), "\n")
	t.Logf("LIST:\n%s", list)
	for _, want := range []string{
		`* LIST () "." "INBOX"`,
		`\Sent) "." "Sent"`,
		`\Drafts) "." "Drafts"`,
		`\Trash) "." "Trash"`,
		`\Junk) "." "Spam"`,
	} {
		if !strings.Contains(list, want) {
			t.Errorf("LIST missing %q", want)
		}
	}

	// LSUB must echo LSUB, not LIST, or the client's subscribed view
	// stays empty.
	lsub := strings.Join(c.ok(`LSUB "" "*"`), "\n")
	if !strings.Contains(lsub, `* LSUB`) {
		t.Errorf("LSUB did not echo LSUB:\n%s", lsub)
	}
	if strings.Contains(lsub, `* LIST`) {
		t.Errorf("LSUB wrongly echoed LIST:\n%s", lsub)
	}
	if !strings.Contains(lsub, `"Sent"`) {
		t.Errorf("LSUB does not list Sent:\n%s", lsub)
	}
}

// The end-to-end flow that hung in the field: keep INBOX selected,
// IDLE, DONE, then copy the sent message into Sent.
func TestThunderbirdCopyToSent(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	c.ok("SELECT INBOX")
	c.n++
	idleTag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s IDLE\r\n", idleTag)
	if line := c.readLine(); !strings.HasPrefix(line, "+") {
		t.Fatalf("IDLE did not park: %q", line)
	}
	fmt.Fprint(c.conn, "DONE\r\n")
	if line := c.readLine(); !strings.Contains(line, "OK") {
		t.Fatalf("DONE did not terminate IDLE: %q", line)
	}

	msg := "From: me@example.com\r\nTo: friend@example.com\r\nSubject: inviata\r\n\r\ntesto\r\n"
	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s APPEND \"Sent\" (\\Seen) {%d}\r\n", tag, len(msg))
	if line := c.readLine(); !strings.HasPrefix(line, "+") {
		t.Fatalf("APPEND to Sent did not ask for the literal: %q", line)
	}
	fmt.Fprint(c.conn, msg+"\r\n")
	if line := c.readLine(); !strings.Contains(line, "OK") || !strings.Contains(line, "APPENDUID") {
		t.Fatalf("APPEND to Sent -> %q, want OK APPENDUID", line)
	}

	// The copy is really there.
	c.ok(`SELECT "Sent"`)
	fetched := strings.Join(c.ok("FETCH 1 (FLAGS BODY.PEEK[])"), "\n")
	if !strings.Contains(fetched, "inviata") {
		t.Errorf("sent message not found in Sent:\n%s", fetched)
	}
}
