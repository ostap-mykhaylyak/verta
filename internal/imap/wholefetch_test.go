package imap

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Thunderbird downloads a whole message with BODY[]<offset.length> in
// fixed-size chunks and reassembles them by the origin octet the server
// echoes. A saved .eml from the server showed the message rotated: the
// final chunk sat at the front and a middle chunk was missing, i.e. the
// chunks were misplaced. Reproduce a chunked whole-message fetch and
// assert it reassembles byte-for-byte.
func TestPartialWholeMessageFetch(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	// A multipart message bigger than several client chunks.
	html := "<html><body>" + strings.Repeat("<p>riga di newsletter</p>", 800) + "</body></html>"
	msg := "From: news@brand.com\r\nSubject: grande\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"B\"\r\n\r\n" +
		"--B\r\nContent-Type: text/plain\r\n\r\ntesto\r\n" +
		"--B\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + html + "\r\n--B--\r\n"
	appendAndSelect(t, c, msg)

	// The whole message, fetched in one shot, for reference.
	full := bodyLiteral(t, c, "FETCH 1 (BODY.PEEK[])")
	if len(full) < 15000 {
		t.Fatalf("message unexpectedly small: %d bytes", len(full))
	}

	// RFC822.SIZE must equal the number of bytes BODY[] actually serves.
	// Thunderbird pre-allocates a buffer of RFC822.SIZE and fills it from
	// the chunked BODY[] fetch; if the body is even one byte longer than
	// the advertised size the surplus wraps and overwrites the front,
	// which shows up as a message rotated by (actual-advertised) bytes.
	sizeResp := strings.Join(c.ok("FETCH 1 (RFC822.SIZE)"), "\n")
	i := strings.Index(sizeResp, "RFC822.SIZE ")
	if i < 0 {
		t.Fatalf("no RFC822.SIZE in %q", sizeResp)
	}
	var size int
	fmt.Sscanf(sizeResp[i:], "RFC822.SIZE %d", &size)
	if size != len(full) {
		t.Errorf("RFC822.SIZE %d != BODY[] length %d (delta %d): a client would wrap the surplus",
			size, len(full), len(full)-size)
	}

	// Fetch it in chunks the way Thunderbird does, and reassemble by
	// placing each chunk at the offset requested.
	got := make([]byte, len(full))
	const chunk = 4096
	for off := 0; off < len(full); off += chunk {
		part := bodyLiteral(t, c, fmt.Sprintf("FETCH 1 (BODY.PEEK[]<%d.%d>)", off, chunk))
		if part == "" {
			t.Fatalf("partial BODY[]<%d.%d> returned empty", off, chunk)
		}
		copy(got[off:], part)
	}
	if string(got) != full {
		// Find the first divergence to make the failure legible.
		n := len(full)
		if len(got) < n {
			n = len(got)
		}
		diff := -1
		for i := 0; i < n; i++ {
			if got[i] != full[i] {
				diff = i
				break
			}
		}
		t.Errorf("chunked whole-message fetch did not reassemble: first diff at byte %d\n got[%d:]=%.60q\nfull[%d:]=%.60q",
			diff, diff, string(got[max0(diff):]), diff, full[max0(diff):])
	}
}

func max0(i int) int {
	if i < 0 {
		return 0
	}
	return i
}
