package smtp

import (
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/ratelimit"
)

// A custom per-recipient message rule of 1/hour must let the first
// message through and refuse the second with a 452, end to end.
func TestGovernorRuleRejectsSecondMessage(t *testing.T) {
	root := t.TempDir()
	gov := ratelimit.NewGovernor([]ratelimit.GovRule{
		{By: ratelimit.ByRecipient, Window: time.Hour, Messages: 1},
	})
	set := Settings{Hostname: "mail.example.com", MaxSize: 64 * 1024, MaxRecipients: 5, Governor: gov}
	backend := Backend{
		IsLocalDomain: func(d string) bool { return d == "example.com" },
		Route:         routeAdmin(root),
		Store:         storeToMaildir,
		Postmaster:    func() string { return "" },
	}
	srv := New(set, backend, 4, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })

	send := func() string {
		c := dial(t, ln.Addr().String())
		c.expect("220")
		c.send("EHLO x.test")
		c.expect("250")
		c.send("MAIL FROM:<a@b.org>")
		c.expect("250")
		c.send("RCPT TO:<admin@example.com>")
		c.expect("250")
		c.send("DATA")
		// The message limit is enforced at DATA, before the 354 prompt.
		var full string
		for {
			line, err := c.r.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			full += line
			if len(line) >= 4 && line[3] == ' ' {
				return full
			}
		}
	}

	if got := send(); got[:3] != "354" {
		t.Fatalf("first message should be accepted, got %q", got)
	}
	if got := send(); got[:3] != "452" {
		t.Errorf("second message should be rate limited (452), got %q", got)
	}
}
