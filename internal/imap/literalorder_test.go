package imap

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A FETCH that mixes single-line items with the big BODY[] literal must
// send the literal LAST, the way Dovecot and every mainstream server
// does. When verta emitted "UID" after the body literal, Thunderbird's
// message cache truncated the body and showed scrambled source on the
// second open. Assert UID and RFC822.SIZE arrive before the literal and
// that nothing but ")" follows it.
func TestBodyLiteralIsLast(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	msg := "From: news@brand.com\r\nSubject: ordine\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		strings.Repeat("riga di corpo\r\n", 200)
	appendAndSelect(t, c, msg)

	// Read the whole FETCH response, literal included, as raw bytes.
	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s UID FETCH 1 (UID RFC822.SIZE BODY[])\r\n", tag)

	first := c.readLine() // * <seq> FETCH (....... {N}
	open := strings.LastIndex(first, "{")
	if open < 0 || !strings.HasSuffix(first, "}") {
		t.Fatalf("expected a literal announcement, got %q", first)
	}

	// Everything before the literal must already carry UID and
	// RFC822.SIZE, and BODY[ must be the last item before the {.
	head := first[:open]
	if !strings.Contains(head, "UID 1") || !strings.Contains(head, "RFC822.SIZE ") {
		t.Errorf("UID/RFC822.SIZE must precede the body literal, got %q", head)
	}
	if i := strings.LastIndex(head, "BODY["); i < 0 || strings.Contains(head[i:], "RFC822.SIZE") || strings.Contains(head[i:], "UID ") {
		t.Errorf("BODY[ must be the final item before the literal, got %q", head)
	}

	// Consume the literal, then the remainder of the line: it must be
	// only ")" — no "UID" or any other item trailing the body.
	n, _ := strconv.Atoi(first[open+1 : len(first)-1])
	if _, err := io.ReadFull(c.r, make([]byte, n)); err != nil {
		t.Fatalf("reading literal: %v", err)
	}
	rest := c.readLine()
	if strings.TrimSpace(rest) != ")" {
		t.Errorf("nothing may follow the body literal but %q did", rest)
	}
	for {
		if strings.HasPrefix(c.readLine(), tag+" ") {
			break
		}
	}
}
