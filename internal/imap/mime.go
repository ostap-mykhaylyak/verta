package imap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"strings"
)

// mimePart is one node of a parsed message: a leaf (text, an
// attachment) or a multipart with children. body is the raw content
// after this part's header — for a multipart it is the whole multipart
// body, so BODY[n] returns it verbatim; rawHeader is this part's own
// header block, for BODY[n.MIME].
type mimePart struct {
	ctype    string // "TEXT", "IMAGE", "MULTIPART"...
	csub     string // "PLAIN", "HTML", "MIXED"...
	params   map[string]string
	encoding string // Content-Transfer-Encoding, e.g. "7BIT", "BASE64"
	disp     string // Content-Disposition media type, e.g. "attachment"
	dispName string // filename= from Content-Disposition

	rawHeader []byte
	body      []byte
	children  []*mimePart
}

// parseMessage parses a full RFC 5322 message into a part tree. It
// never fails: a message it cannot dissect becomes a single text/plain
// leaf, which is what a client falls back to displaying anyway.
func parseMessage(data []byte) *mimePart {
	hdr, body := splitHeaderBody(data)
	return buildPart(hdr, body)
}

// buildPart constructs a part from its raw header block and its raw
// body, recursing into multipart children.
func buildPart(rawHeader, body []byte) *mimePart {
	p := &mimePart{
		ctype: "TEXT", csub: "PLAIN", encoding: "7BIT",
		params:    map[string]string{"CHARSET": "US-ASCII"},
		rawHeader: rawHeader,
		body:      body,
	}

	h := parseHeader(rawHeader)
	if ct := h.Get("Content-Type"); ct != "" {
		if mediaType, params, err := mime.ParseMediaType(ct); err == nil {
			if t, st, ok := strings.Cut(mediaType, "/"); ok {
				p.ctype, p.csub = strings.ToUpper(t), strings.ToUpper(st)
			}
			p.params = upperKeys(params)
		}
	}
	if e := h.Get("Content-Transfer-Encoding"); e != "" {
		p.encoding = strings.ToUpper(strings.TrimSpace(e))
	}
	if cd := h.Get("Content-Disposition"); cd != "" {
		if disp, params, err := mime.ParseMediaType(cd); err == nil {
			p.disp = strings.ToUpper(disp)
			p.dispName = params["filename"]
		}
	}

	if p.ctype == "MULTIPART" {
		if boundary := p.params["BOUNDARY"]; boundary != "" {
			mr := multipart.NewReader(bytes.NewReader(body), boundary)
			for {
				part, err := mr.NextRawPart()
				if err != nil {
					break
				}
				childBody, _ := io.ReadAll(part)
				p.children = append(p.children, buildPart(rawHeaderOf(part.Header), childBody))
			}
		}
		if len(p.children) == 0 {
			// A part that claims to be multipart but yields no children
			// (missing boundary, a body we could not split) must not be
			// reported as a multipart leaf: a client cannot render that
			// and shows an empty message. Fall back to a single text
			// part so the raw content is at least visible.
			p.ctype, p.csub = "TEXT", "PLAIN"
			p.params = map[string]string{"CHARSET": "US-ASCII"}
		}
	}
	return p
}

// structure renders the IMAP BODYSTRUCTURE (extended) or BODY
// (non-extended) of a part, recursively.
func structure(p *mimePart, extended bool) string {
	if len(p.children) > 0 {
		var b strings.Builder
		b.WriteByte('(')
		for _, c := range p.children {
			b.WriteString(structure(c, extended))
		}
		fmt.Fprintf(&b, " %s", quote(p.csub))
		if extended {
			fmt.Fprintf(&b, " %s NIL NIL NIL", paramList(p.params))
		}
		b.WriteByte(')')
		return b.String()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "(%s %s %s NIL NIL %s %d",
		quote(p.ctype), quote(p.csub), paramList(p.params), quote(p.encoding), len(p.body))
	if p.ctype == "TEXT" {
		fmt.Fprintf(&b, " %d", countLines(p.body))
	}
	if extended {
		// body MD5, then disposition, language, location.
		fmt.Fprintf(&b, " NIL %s NIL NIL", disposition(p))
	}
	b.WriteByte(')')
	return b.String()
}

// disposition renders the body-fld-dsp of a part: (disp (params)) or
// NIL.
func disposition(p *mimePart) string {
	if p.disp == "" {
		return "NIL"
	}
	params := "NIL"
	if p.dispName != "" {
		params = fmt.Sprintf("(%s %s)", quote("FILENAME"), quote(p.dispName))
	}
	return fmt.Sprintf("(%s %s)", quote(p.disp), params)
}

// resolveSection returns the bytes for a BODY[section] where section
// addresses a part ("1", "1.2") with an optional ".MIME"/".HEADER"/
// ".TEXT" suffix. An empty result means the section does not exist.
func resolveSection(root *mimePart, section string) string {
	fields := strings.Split(section, ".")
	suffix := ""
	if n := len(fields); n > 0 {
		switch strings.ToUpper(fields[n-1]) {
		case "MIME", "HEADER", "TEXT":
			suffix = strings.ToUpper(fields[n-1])
			fields = fields[:n-1]
		}
	}

	node := root
	for _, f := range fields {
		idx, err := strconv.Atoi(f)
		if err != nil || idx < 1 {
			return ""
		}
		if len(node.children) == 0 {
			// A non-multipart part: part 1 is the part itself, and
			// there is no deeper structure.
			if idx != 1 || len(fields) > 1 {
				return ""
			}
		} else {
			if idx > len(node.children) {
				return ""
			}
			node = node.children[idx-1]
		}
	}

	switch suffix {
	case "MIME":
		return string(node.rawHeader)
	case "HEADER":
		return headerOf(node.body)
	case "TEXT":
		return bodyOf(node.body)
	default:
		return string(node.body)
	}
}

// --- small helpers ---

// splitHeaderBody splits a message into its header block (through the
// terminating blank line) and its body.
func splitHeaderBody(data []byte) (header, body []byte) {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return data[:i+4], data[i+4:]
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return data[:i+2], data[i+2:]
	}
	return data, nil
}

// parseHeader parses a raw header block.
func parseHeader(raw []byte) textproto.MIMEHeader {
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	h, _ := tp.ReadMIMEHeader() // trailing error at EOF is expected
	return h
}

// rawHeaderOf reconstructs a header block from a parsed MIME header,
// for a child part whose exact bytes multipart did not hand back.
func rawHeaderOf(h textproto.MIMEHeader) []byte {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// upperKeys uppercases a param map's keys, as IMAP renders them.
func upperKeys(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToUpper(k)] = v
	}
	return out
}

// paramList renders a Content-Type parameter list, or NIL when empty.
func paramList(params map[string]string) string {
	if len(params) == 0 {
		return "NIL"
	}
	// Sorted for a stable, testable rendering.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	b.WriteByte('(')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s %s", quote(k), quote(params[k]))
	}
	b.WriteByte(')')
	return b.String()
}

func countLines(body []byte) int { return bytes.Count(body, []byte("\n")) }

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
