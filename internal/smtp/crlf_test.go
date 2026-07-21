package smtp

import "testing"

func TestEnsureCRLF(t *testing.T) {
	cases := map[string]string{
		"a\nb\n":        "a\r\nb\r\n",      // bare LF -> CRLF
		"a\r\nb\r\n":    "a\r\nb\r\n",      // already CRLF, unchanged
		"a\r\nb\nc\r\n": "a\r\nb\r\nc\r\n", // mixed
		"noeol":         "noeol",           // no line ending
		"\n":            "\r\n",
		"":              "",
	}
	for in, want := range cases {
		if got := string(ensureCRLF([]byte(in))); got != want {
			t.Errorf("ensureCRLF(%q) = %q, want %q", in, got, want)
		}
	}
	// A message stored this way has RFC822.SIZE matching a client that
	// counts CRLF: one extra byte per line versus the bare-LF form.
	body := "Header: x\nline one\nline two\n"
	fixed := ensureCRLF([]byte(body))
	if len(fixed) != len(body)+3 { // three LFs became CRLF
		t.Errorf("size after CRLF normalization = %d, want %d", len(fixed), len(body)+3)
	}
}
