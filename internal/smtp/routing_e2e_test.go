package smtp

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/filter"
	"github.com/ostap-mykhaylyak/verta/internal/routing"
	"github.com/ostap-mykhaylyak/verta/internal/storage"
)

// A single inbound message to a distribution alias must fan out: land in
// every local mailbox (honoring each mailbox's filters) and be forwarded
// to every external target. Drive it through a real session end to end.
func TestRoutedDeliveryFiltersAndForwards(t *testing.T) {
	root := t.TempDir()
	var forwards []string
	var forwardDomain string

	backend := Backend{
		IsLocalDomain: func(d string) bool { return d == "example.com" },
		Route: func(email string) (routing.Plan, bool) {
			if email != "sales@example.com" {
				return routing.Plan{}, false
			}
			mario := storage.Mailbox{Email: "mario@example.com", Dir: filepath.Join(root, "mario"), UID: -1, GID: -1}
			lucia := storage.Mailbox{Email: "lucia@example.com", Dir: filepath.Join(root, "lucia"), UID: -1, GID: -1}
			return routing.Plan{
				Local: []routing.Local{
					{Mailbox: mario, Filters: []filter.Rule{{From: "boss@", Folder: "Priority", Flagged: true, Stop: true}}},
					{Mailbox: lucia},
				},
				Remote: []string{"backup@gmail.com"},
				Found:  true,
			}, true
		},
		Store: storeToMaildir,
		Forward: func(from, dom, rcpt string, msg []byte) error {
			forwardDomain = dom
			forwards = append(forwards, rcpt)
			return nil
		},
		Postmaster: func() string { return "" },
	}
	addr := startInbound(t, root, backend)

	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO client.test")
	c.expect("250")
	c.send("MAIL FROM:<boss@example.com>")
	c.expect("250")
	c.send("RCPT TO:<sales@example.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	c.send("From: boss@example.com\r\nSubject: piano\r\n\r\ndecisioni\r\n.")
	c.expect("250")

	// mario's filter fires: the message is in his Priority folder, in
	// cur/ with the \Flagged (F) flag, not in his INBOX.
	// The info separator differs by OS (":2," on unix, ";2," on Windows),
	// so key on the flag part "2,F".
	prio := readDirNames(t, filepath.Join(root, "mario", ".Priority", "cur"))
	if len(prio) != 1 || !strings.Contains(prio[0], "2,F") {
		t.Errorf("mario Priority/cur = %v, want one flagged message", prio)
	}
	if n := readDirNames(t, filepath.Join(root, "mario", "new")); len(n) != 0 {
		t.Errorf("mario INBOX should be empty (filtered away), got %v", n)
	}

	// lucia has no filter: plain INBOX delivery in new/.
	if n := readDirNames(t, filepath.Join(root, "lucia", "new")); len(n) != 1 {
		t.Errorf("lucia INBOX = %v, want one message", n)
	}

	// The external target was forwarded, with example.com as the SRS
	// forwarding domain.
	if len(forwards) != 1 || forwards[0] != "backup@gmail.com" {
		t.Errorf("forwards = %v, want [backup@gmail.com]", forwards)
	}
	if forwardDomain != "example.com" {
		t.Errorf("forward domain = %q, want example.com", forwardDomain)
	}
}

// A filter that discards a message accepts it on the wire (no bounce)
// but stores nothing.
func TestFilterDiscardStoresNothing(t *testing.T) {
	root := t.TempDir()
	backend := Backend{
		IsLocalDomain: func(d string) bool { return d == "example.com" },
		Route: func(email string) (routing.Plan, bool) {
			mb := storage.Mailbox{Email: "mario@example.com", Dir: filepath.Join(root, "mario"), UID: -1, GID: -1}
			return routing.Plan{
				Local: []routing.Local{{Mailbox: mb, Filters: []filter.Rule{{From: "spam@", Discard: true}}}},
				Found: true,
			}, true
		},
		Store:      storeToMaildir,
		Postmaster: func() string { return "" },
	}
	addr := startInbound(t, root, backend)
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("MAIL FROM:<spam@bad.com>")
	c.expect("250")
	c.send("RCPT TO:<mario@example.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	c.send("From: spam@bad.com\r\nSubject: buy\r\n\r\nx\r\n.")
	c.expect("250") // accepted, not bounced
	if n := readDirNames(t, filepath.Join(root, "mario", "new")); len(n) != 0 {
		t.Errorf("a discarded message must not be stored, got %v", n)
	}
}

func startInbound(t *testing.T, root string, b Backend) string {
	t.Helper()
	set := Settings{Hostname: "mail.example.com", MaxSize: 64 * 1024, MaxRecipients: 5}
	srv := New(set, b, 4, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	return ln.Addr().String()
}

func readDirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}
