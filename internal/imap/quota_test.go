package imap

import (
	stdtls "crypto/tls"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// The QUOTA extension (RFC 2087) must be advertised and report the
// account's usage and limit as STORAGE in kibibytes, so a client can
// draw a usage bar.
func TestQuotaExtension(t *testing.T) {
	root := t.TempDir()
	srv := New(Settings{Hostname: "mail.example.com", ImplicitTLS: true, MaxSize: 1 << 20},
		Backend{
			Authenticate: func(email, pw, ip string) (string, error) {
				if email == "admin@example.com" && pw == "pw" {
					return root, nil
				}
				return "", errors.New("bad")
			},
			Quota: func(user string) (int64, int64) {
				return 3 * 1024 * 1024, 10 * 1024 * 1024 // 3 MiB used, 10 MiB limit
			},
		}, 8, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(stdtls.NewListener(ln, testTLSConfig(t)))
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })

	c := dial(t, ln.Addr().String())
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	if caps := strings.Join(c.ok("CAPABILITY"), " "); !strings.Contains(caps, "QUOTA") {
		t.Errorf("QUOTA not advertised: %s", caps)
	}

	root1 := strings.Join(c.ok("GETQUOTAROOT INBOX"), "\n")
	if !strings.Contains(root1, `QUOTAROOT "INBOX" ""`) {
		t.Errorf("GETQUOTAROOT missing the root line:\n%s", root1)
	}
	// 3 MiB = 3072 KiB, 10 MiB = 10240 KiB.
	if !strings.Contains(root1, `QUOTA "" (STORAGE 3072 10240)`) {
		t.Errorf("GETQUOTAROOT missing/incorrect STORAGE:\n%s", root1)
	}

	q := strings.Join(c.ok(`GETQUOTA ""`), "\n")
	if !strings.Contains(q, `QUOTA "" (STORAGE 3072 10240)`) {
		t.Errorf("GETQUOTA wrong:\n%s", q)
	}
}

// With no limit the resource list is empty (clients read "unlimited"),
// and SETQUOTA is refused.
func TestQuotaUnlimitedAndSetRefused(t *testing.T) {
	root := t.TempDir()
	srv := New(Settings{Hostname: "mail.example.com", ImplicitTLS: true, MaxSize: 1 << 20},
		Backend{
			Authenticate: func(email, pw, ip string) (string, error) {
				if email == "admin@example.com" && pw == "pw" {
					return root, nil
				}
				return "", errors.New("bad")
			},
			Quota: func(user string) (int64, int64) { return 500, 0 }, // no limit
		}, 8, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(stdtls.NewListener(ln, testTLSConfig(t)))
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })

	c := dial(t, ln.Addr().String())
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.login()

	if got := strings.Join(c.ok(`GETQUOTA ""`), "\n"); !strings.Contains(got, `QUOTA "" ()`) {
		t.Errorf("unlimited quota should report an empty resource list:\n%s", got)
	}
	_, tagged := c.do(`SETQUOTA "" (STORAGE 100000)`)
	if !strings.HasPrefix(tagged, "NO") {
		t.Errorf("SETQUOTA must be refused, got %q", tagged)
	}
}
