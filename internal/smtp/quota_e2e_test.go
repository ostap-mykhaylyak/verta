package smtp

import (
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/storage"
)

// A message to a full mailbox must be deferred with 452 (retry), never
// accepted and dropped; under quota it is delivered normally.
func TestQuotaDefersWhenFull(t *testing.T) {
	root := t.TempDir()
	full := false
	set := Settings{Hostname: "mail.example.com", MaxSize: 64 * 1024, MaxRecipients: 5}
	backend := Backend{
		IsLocalDomain: func(d string) bool { return d == "example.com" },
		Route:         routeAdmin(root),
		Store:         storeToMaildir,
		Quota: func(mb storage.Mailbox, size int64) (bool, string) {
			if full {
				return false, "mailbox is full"
			}
			return true, ""
		},
		Postmaster: func() string { return "" },
	}
	srv := New(set, backend, 4, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })

	send := func(wantFinal string) {
		c := dial(t, ln.Addr().String())
		c.expect("220")
		c.send("EHLO x.test")
		c.expect("250")
		c.send("MAIL FROM:<a@b.org>")
		c.expect("250")
		c.send("RCPT TO:<admin@example.com>")
		c.expect("250")
		c.send("DATA")
		c.expect("354")
		c.send("Subject: hi\r\n\r\nbody\r\n.")
		c.expect(wantFinal)
	}

	send("250") // under quota: delivered
	full = true
	send("452") // over quota: deferred, not dropped
}
