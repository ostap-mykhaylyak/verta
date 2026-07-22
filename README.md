# verta

[![CI](https://github.com/ostap-mykhaylyak/verta/actions/workflows/ci.yml/badge.svg)](https://github.com/ostap-mykhaylyak/verta/actions/workflows/ci.yml)

Enterprise mail server in Go. A single static binary that replaces
Postfix, Dovecot and Rspamd: SMTP, IMAP and POP3, sender
authentication, spam and virus filtering, outbound reputation
management, and an administrative API.

Built for hosting providers, multi-domain mail hosting, dedicated
servers, VPS and LXD/LXC containers.

---

## Contents

- [Design principles](#design-principles)
- [Installation](#installation)
- [Configuration layout](#configuration-layout)
- [Domains and mailboxes](#domains-and-mailboxes)
- [Aliases, forwarding and filters](#aliases-forwarding-and-filters)
- [TLS certificates](#tls-certificates)
- [SMTP](#smtp)
- [Authentication and submission](#authentication-and-submission)
- [IMAP and POP3](#imap-and-pop3)
- [Outbound queue](#outbound-queue)
- [SPF, DKIM and DMARC](#spf-dkim-and-dmarc)
- [Spam filtering](#spam-filtering)
- [Antivirus](#antivirus)
- [Blacklists](#blacklists)
- [Rate limiting](#rate-limiting)
- [Outbound IP rotation](#outbound-ip-rotation)
- [Reputation and warm-up](#reputation-and-warm-up)
- [Administrative API](#administrative-api)
- [Running in a container](#running-in-a-container)
- [Logging](#logging)
- [Status](#status)
- [Diagnostics](#diagnostics)
- [Command reference](#command-reference)
- [DNS records](#dns-records)
- [Building](#building)

---

## Design principles

**Secure by default.** Verta cannot be configured into an open relay:
on port 25 a recipient is either a local mailbox or the transaction is
refused, and no code path exists that would relay it. Authentication
is offered only over TLS. Anything not explicitly enabled stays off,
and an insecure configuration — the admin API without keys, spam
thresholds in the wrong order, a container without a public address —
is a startup error, not a warning.

**Operable.** Every subsystem writes structured JSON events. Three
diagnostic commands verify the deployment against reality, including a
real open-relay attempt against the running server. A broken domain
file takes down that domain, not the server.

**Single binary.** Static, no runtime dependencies, `amd64` and
`arm64`.

---

## Installation

Download the bundle for your architecture, unpack it and let the
binary provision the system:

```sh
curl -LO https://github.com/ostap-mykhaylyak/verta/releases/download/v0.3.0/verta-v0.3.0-linux-amd64.tar.gz
tar xzf verta-*.tar.gz && cd verta-*
sudo ./verta --init
sudo systemctl daemon-reload
sudo systemctl enable --now verta
verta --status
```

`--init` installs the binary to `/usr/sbin/verta`, creates
`/etc/verta` with its `domains/` directory, `/var/log/verta` and
`/var/lib/verta` with the queue and DKIM directories, writes a
commented configuration and an example domain file, and installs the
systemd unit. It never overwrites an existing configuration, so
**running it again from a newer bundle is the upgrade path**:

```sh
tar xzf verta-v0.3.0-linux-amd64.tar.gz && cd verta-v0.3.0-linux-amd64
sudo ./verta --init            # replaces the binary, keeps your config
sudo systemctl restart verta
```

Verify the download first if you like:

```sh
curl -LO https://github.com/ostap-mykhaylyak/verta/releases/latest/download/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Before the server is useful you need a hostname, a domain and a
certificate — `init` prints the steps, and:

```sh
verta --check-config
verta --audit && verta --security-check
```

will tell you what is still missing.

To remove everything verta owns — configuration, domains, logs,
queue, DKIM keys, learned spam corpus and the unit:

```sh
verta --purge          # lists what it will delete and asks first
verta --purge --yes    # unattended
```

Purge destroys the DKIM private keys and every queued message, so it
requires the confirmation to be typed in full. It stops the service,
removes the configuration, logs and state, and finally the binary
itself. Mailboxes outside those paths are not touched.

Building from source is described in [Building](#building).

---

## Configuration layout

```
/etc/verta/
├── config.yaml                    the server: listeners, TLS, policy
└── domains/
    ├── example.com.yaml           one file per hosted domain
    └── studenti.ente.it.yaml
```

Domains live outside the main configuration deliberately. Adding a
customer, changing one mailbox password or handing a domain to a
provisioning script must not mean rewriting the file that also holds
the listeners and the TLS settings — and a syntax error in one
customer's file must not take the whole server down. A domain file
that fails to parse is logged and skipped; every other domain keeps
working.

Apply any change with `verta reload` (or `systemctl reload verta`).
A configuration that fails to load is never applied: the previous one
stays active and the error is logged.

The directory can be moved:

```yaml
# /etc/verta/config.yaml
domains_dir: /etc/verta/domains
```

When unset it resolves next to the configuration file, which keeps a
staging copy self-contained.

---

## Domains and mailboxes

One file per domain. **The file name is the domain**: verta refuses a
file whose `name` key disagrees with it, so a typo cannot silently
create a domain nobody meant to host.

### Virtual mailboxes

```yaml
# /etc/verta/domains/example.com.yaml
name: example.com
dkim_selector: default

storage:
  type: virtual

users:
  - email: admin@example.com
    maildir: /var/mail/example.com/admin
    password_hash: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$..."

  - email: info@example.com
    maildir: /var/mail/example.com/info
    password_hash: "$argon2id$v=19$m=65536,t=3,p=4$..."
```

### System-user mailboxes

A domain can map to one real Linux account. Mail is delivered to that
account's Maildir with its UID and GID, honouring POSIX permissions:

```yaml
# /etc/verta/domains/ostap.dev.yaml
name: ostap.dev

storage:
  type: system_user
  user: ostap
  home: /home/ostap        # optional, defaults to /home/<user>
  maildir: "{home}/mail"   # optional, {home} expands
  password_hash: "$argon2id$..."
```

Mail for `ostap@ostap.dev` lands in `/home/ostap/mail/{cur,new,tmp}`.
Only the bound account exists in that domain; any other recipient is
rejected with `550`.

### Passwords

Never stored in clear. Generate a hash with:

```sh
verta --hash-password        # reads from stdin, prints an argon2id hash
```

Argon2id (RFC 9106 parameters) and bcrypt are accepted; any other
format is refused at load time. A mailbox without a `password_hash`
can receive mail, but nobody can log in to it — which is exactly what
you want for a catch-all or an alias target.

---

## Aliases, forwarding and filters

Beyond a plain mailbox, an address can fan out to several destinations —
other mailboxes, external addresses, or both — and mail can be sorted or
dropped on delivery. All of it lives in the domain file; a domain that
uses none of these keys behaves exactly as before.

### Aliases

An alias maps a local part to one or more **targets**. A target is a
local mailbox (delivery), several (a distribution list), or an address on
another host (a forward). Aliases resolve recursively — an alias may
point at another alias or at a forwarding mailbox — with loop and depth
protection.

```yaml
name: example.com
users:
  - email: mario@example.com
    maildir: /var/mail/example.com/mario

aliases:
  info: mario@example.com                        # one mailbox
  sales: [mario@example.com, lucia@example.com]  # distribution list
  webmaster: someone@gmail.com                   # external target = forward
```

`info@example.com` and `sales@example.com` need no mailbox of their own.
A target with no `@` is taken to be a local part in the same domain.

### Catch-all

`catch_all` receives every address in the domain that matches neither a
mailbox nor an alias. Leave it unset to reject unknown addresses with
`550`.

```yaml
catch_all: mario@example.com
```

**Forward an entire domain.** A domain with *no* mailboxes and a
catch-all pointing at an external address forwards everything it
receives — the "one Gmail for a whole domain" case:

```yaml
# /etc/verta/domains/studenti.scuola.it.yaml
name: studenti.scuola.it
catch_all: classe3b@gmail.com
```

### Mailbox forwarding

`forward_to` on a mailbox sends a copy of every delivered message
onward. A local copy is kept by default; `keep_local: false` makes it
forward-only.

```yaml
users:
  - email: mario@example.com
    maildir: /var/mail/example.com/mario
    forward_to: [backup@gmail.com]
    keep_local: true      # default; false = do not store, forward only
```

### Filters

Per-mailbox delivery rules, evaluated top to bottom. Every condition set
on a rule must match (they are ANDed); actions accumulate across matching
rules up to the first rule with `stop: true`.

```yaml
users:
  - email: mario@example.com
    maildir: /var/mail/example.com/mario
    filters:
      - from: "newsletter@"        # sender substring
        folder: Newsletters        # file into this folder
        stop: true
      - subject: "[URGENT]"
        flagged: true              # mark important
      - to: sales@example.com      # matches To or Cc
        folder: Sales
      - header: "X-Mailer: sendgrid"
        folder: Bulk
      - larger_than: 5242880       # bytes
        folder: Big
      - from: spam@spammer.tld
        discard: true              # accept on the wire, store nothing
```

| Condition | Matches (case-insensitive) |
|---|---|
| `from` | substring of the From header |
| `to` | substring of To **or** Cc |
| `subject` | substring of Subject |
| `header` | `"Name: value"` — header present, value contains the substring |
| `larger_than` | message strictly larger than N bytes |

| Action | Effect |
|---|---|
| `folder` | deliver into this mailbox folder (created on demand) |
| `junk` | deliver into the Spam folder |
| `seen` | mark read on arrival |
| `flagged` | mark flagged / important |
| `forward_to` | send a copy to an address |
| `discard` | accept but store nothing (no bounce) |
| `stop` | stop evaluating further rules |

A spam verdict from the [antispam pipeline](#spam-filtering) always wins
over a `folder` rule (the message goes to Spam).

### Forwarding and SPF (SRS)

Any forward — an external alias, a `forward_to`, an external catch-all or
a filter's `forward_to` — leaves through the [outbound queue](#outbound-queue)
with its envelope sender rewritten by **SRS** (Sender Rewriting Scheme):

```
news@brand.com  ->  SRS0=hash=tt=brand.com=news@<forwarding-domain>
```

so the destination evaluates SPF against a domain verta is authorised to
send for, and the forward is not rejected as a spoof. A bounce returns to
that address, is verified (HMAC + timestamp) and relayed to the original
sender — never an open backscatter relay.

SRS needs a stable secret, in the **main** configuration:

```yaml
# /etc/verta/config.yaml
forwarding:
  srs_secret: "…"   # verta --init generates one; or: openssl rand -hex 32
```

Keep it stable (a bounce may return weeks later) and identical across a
cluster. An empty secret disables SRS: forwards keep the original
envelope sender and may be rejected downstream.

For a forward to be accepted, **the forwarding domain's SPF must list
verta's IP**, e.g. for `studenti.scuola.it`:

```
studenti.scuola.it.  IN MX  10 mail.example.com.
studenti.scuola.it.  IN TXT "v=spf1 ip4:203.0.113.10 -all"
```

DKIM-signed mail forwards with its signature intact (verta never alters
the body); unsigned mail from a strict-DMARC sender may still be filtered
downstream — a limitation of any forwarder, not of verta.

---

## TLS certificates

Certificates are **wildcards issued on the configured domain**, in the
standard Let's Encrypt layout. There is never a per-subdomain
directory:

```
mail.example.com        →  /etc/letsencrypt/live/example.com/
mail.studenti.ente.it   →  /etc/letsencrypt/live/studenti.ente.it/
```

```yaml
tls:
  cert_root: /etc/letsencrypt/live
  min_version: "1.2"        # or "1.3"; SSLv3/1.0/1.1 are never offered
  expiry_warn_days: 14
```

The "base domain" is exactly the domain declared in `domains/` — no
heuristics that would get `studenti.ente.it` wrong. SNI resolves the
client-sent name to the longest configured domain suffix, so with both
`ente.it` and `studenti.ente.it` hosted, the more specific one wins.

Renewed certificates are picked up on `verta reload` and
automatically every 12 hours. A missing certificate is a warning, not
a crash: the domains whose certificates load keep working. The
protocols that carry credentials — submission, IMAP, POP3 and the API
— refuse to start without one.

If verta starts before the certificate is in place — a common order
on a first install — those listeners are skipped, and **`verta reload`
brings them up as soon as the certificate is present**, no restart
needed. `verta --status` reports the listeners actually bound, so you
can see exactly which ones came up.

---

## SMTP

```yaml
listeners:
  smtp:
    address: ":25"          # inbound MX
  submission:
    address: ":587"         # authenticated submission, STARTTLS
  smtps:
    address: ":465"         # authenticated submission, implicit TLS

smtp:
  max_size: 26214400        # 25 MB, advertised via EHLO SIZE
  max_recipients: 100
```

An empty address disables a listener.

Port 25 accepts mail **only for hosted domains**. Anything else gets
`554 5.7.1 relay access denied` — this is structural, not a setting.
`VRFY` and `EXPN` are permanently disabled (user enumeration), and
`AUTH` is refused outright on port 25.

Supported: `EHLO`/`HELO`, `PIPELINING`, `SIZE`, `8BITMIME`,
`SMTPUTF8`, `STARTTLS`.

---

## Authentication and submission

Submission requires authentication, and authentication requires TLS:
`AUTH PLAIN` and `AUTH LOGIN` are advertised only once the channel is
encrypted, so a password never crosses the wire in the clear. The
envelope sender is forced to the authenticated user — a spoofed
`MAIL FROM` is refused with `553` and logged.

```yaml
auth:
  max_failures: 10          # then the user AND the source IP lock out
  lockout_minutes: 15
```

Failed attempts get a progressive delay (250 ms doubling, capped at
4 s) before the reply. An unknown user costs the same time as a wrong
password, so the two cannot be told apart.

---

## IMAP and POP3

```yaml
listeners:
  imap:
    address: ":143"         # STARTTLS
  imaps:
    address: ":993"         # implicit TLS
  pop3:
    address: ":110"         # STLS
  pop3s:
    address: ":995"         # implicit TLS
```

IMAP4rev1 (RFC 3501) with `IDLE` (RFC 2177) and `MOVE` (RFC 6851):
`SELECT`, `EXAMINE`, `FETCH`, `STORE`, `SEARCH`, `COPY`, `MOVE`,
`EXPUNGE`, `APPEND`, `UID`, `LIST`, `STATUS`, `CREATE`, `DELETE`.
Flags (`\Seen`, `\Answered`, `\Flagged`, `\Deleted`, `\Draft`) are
stored the standard Maildir way, in the file name.

POP3 (RFC 1939): `USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `RETR`,
`DELE`, `TOP`, `RSET`, `QUIT`.

UIDs are stable across sessions and never reused, persisted per
mailbox. If that state is ever lost, `UIDVALIDITY` changes so clients
resynchronise instead of silently mapping stale UIDs onto different
messages.

Folders follow Maildir++: `INBOX` is the mailbox root, everything else
is a `.`-prefixed subdirectory (`.Sent`, `.Drafts`, `.Trash`,
`.Spam`). The standard folders are created on first login and tagged
with their RFC 6154 special-use attributes (`\Sent`, `\Drafts`,
`\Trash`, `\Junk` on Spam), so a client maps its own Sent/Drafts/
Trash/Junk to them with no configuration. `\Junk` is the Spam folder,
so the user's junk and the server's spam quarantine are one place.

---

## Outbound queue

```yaml
queue:
  dir: /var/lib/verta/queue
  max_attempts: 10
```

One JSON envelope per recipient, written atomically, surviving
restarts. Delivery resolves the destination MX (falling back to the
domain itself per RFC 5321) and uses STARTTLS opportunistically.

- **4xx or a network error** → retry with exponential backoff, 1 minute
  doubling to a 4-hour cap.
- **5xx** → immediate bounce (RFC 3464 delivery status notification).
- **Retries exhausted** → bounce.

A message with a null reverse-path is never bounced, which is what
stops two servers from bouncing at each other forever.

---

## SPF, DKIM and DMARC

### Inbound

```yaml
mail_auth:
  enabled: true
  enforce: true     # false: annotate and log, take no action
```

Every message on port 25 is checked and stamped with an
`Authentication-Results` header (RFC 8601):

- **SPF** (RFC 7208), full evaluation including macros. A null
  reverse-path falls back to checking the HELO name.
- **DKIM** verification (RFC 6376).
- **DMARC** (RFC 7489) with relaxed or strict alignment computed on
  the *organizational* domain via the public suffix list, so
  `a.b.example.co.uk` aligns to `example.co.uk`. `sp=` and `pct=` are
  honoured.

With `enforce: true`, `p=reject` answers `550` at DATA and
`p=quarantine` delivers into `.Spam`. A DNS temporary failure degrades
to accept: losing mail to a flaky resolver is worse than delivering
it.

### Outbound

Mail is DKIM-signed automatically once a domain has a key:

```sh
verta --generate-dkim example.com     # prints the DNS TXT record
```

```yaml
dkim:
  dir: /var/lib/verta/dkim          # <dir>/<domain>/<selector>.pem
```

RSA 2048, relaxed/relaxed canonicalisation. The selector comes from
the domain file (`dkim_selector`, default `default`).
`generate-dkim` never overwrites an existing key — run against a
domain that already has one, it re-prints the published record. A
domain without a key simply sends unsigned: signing is never a
delivery blocker.

`verta --security-check` compares the **published** key against the
local one, because a mismatch makes every signature fail and nothing
else would notice.

---

## Spam filtering

```yaml
antispam:
  enabled: true
  bayes_file: /var/lib/verta/bayes
  tag_score: 5              # stamp X-Spam-Status: Yes
  quarantine_score: 10      # deliver into .Spam
  reject_score: 20          # refuse at DATA with 550
  reject_executables: true
```

The thresholds must escalate (`tag ≤ quarantine ≤ reject`); any other
order is refused at load time, because it would silently invert the
operator's intent.

A **Bayesian classifier** trained on your own corpus, combined with
heuristics over headers, links and attachments: missing `Message-ID`
or `Date`, display-name spoofing (`"servizio@banca.it" <thief@evil>`),
all-caps subjects, raw-IP links, spaced-out text.

The classifier stays silent until it has seen at least 20 ham and 20
spam messages — an untrained filter guessing from a handful of
examples is worse than no filter at all. Probabilities are combined in
log space, so a long message cannot underflow to a nonsensical score,
and ham evidence is weighted double, because a false positive costs
the user far more than a false negative.

**Authenticated mail is credited.** A message that passes DMARC (or is
at least DKIM- or SPF-authenticated) comes from an accountable domain —
if it turns out to be spam, you block the domain — so its score is
discounted (`DMARC_PASS`, shown in `X-Spam-Status`). Ordinary heuristic
noise, like a forwarded newsletter with many links, one on a URI
blacklist, no longer bounces legitimate authenticated mail. A blatantly
spammy message that happens to be authenticated still scores over the
threshold and is caught.

Executable attachments (`.exe`, `.scr`, `.js`, `.vbs`, …) are refused
outright whatever the score, and a double extension —
`fattura.pdf.exe`, which a client hiding known extensions shows as
`fattura.pdf` — is flagged as the disguise it is.

---

## Antivirus

```yaml
antivirus:
  enabled: true
  socket: /var/run/clamav/clamd.ctl     # or host:port
  timeout_seconds: 30
  reject_on_error: false                # true: defer when clamd is down
```

ClamAV over its socket using `INSTREAM`: no temporary file is written
and clamd needs no access to the queue. A confirmed virus is **never
delivered**, not even quarantined.

---

## Blacklists

```yaml
blacklist:
  enabled: true
  dnsbl:                    # queried with the connecting IP
    - zen.spamhaus.org
    - b.barracudacentral.org
    - dnsbl.sorbs.net
    - dnsbl-1.uceprotect.net
  uribl:                    # queried with hostnames found in the body
    - dbl.spamhaus.org
    - multi.uribl.com
  reject_listed: false      # true: refuse a listed IP outright
  cache_minutes: 60
```

Answers are cached: list operators rate-limit, and eventually block,
heavy queriers. Only answers in `127.0.0.0/8` count as a listing, so a
wildcard-hijacking resolver cannot condemn every sender. Private and
loopback space is never queried at all — that would leak your internal
topology to the list operator.

Start with `reject_listed: false` and let listings contribute to the
spam score; turn it on once you trust your lists.

---

## Rate limiting

Token buckets, burst equal to the rate, refilling continuously.

```yaml
rate_limit:
  inbound:                  # per source IP, per minute
    ip:
      connections_per_minute: 30
      messages_per_minute: 100
      recipients_per_minute: 500

  outbound:                 # per authenticated user, per hour
    user:
      messages_per_hour: 500
      recipients_per_hour: 1000
```

Inbound limits protect against floods and scans (`421`/`452`).
Outbound limits contain a compromised account: the credentials still
work, but the damage is bounded, and the event is logged.

Either can be disabled explicitly with `enabled: false`, which
`verta --audit` reports as a failure.

### Custom rules

Layered on top of the two built-ins, `rate_limit.rules` keys a token
bucket on any transaction **dimension**, so a limit can apply per
recipient, per recipient domain, per sender mailbox, per sender domain
or per IP:

```yaml
rate_limit:
  # ...inbound / outbound above...
  rules:
    - by: recipient_domain     # don't hammer any one destination
      messages: 200            # whole messages…
      window: 1h               # …per this window (Go duration; default 1h)
    - by: recipient_domain     # …but allow more to Gmail (override)
      match: gmail.com
      messages: 1000
    - by: recipient            # protect a mailbox from a bombing run
      direction: inbound
      recipients: 100          # count RCPTs, not messages
    - by: sender_mailbox       # a trusted bulk sender gets more headroom
      match: newsletter@example.com
      direction: outbound
      messages: 5000
```

| Field | Meaning |
|---|---|
| `by` | dimension: `ip`, `sender_domain`, `sender_mailbox`, `recipient`, `recipient_domain` |
| `match` | pin the rule to one value — an **override** that replaces the generic limit for it; omit for a generic rule (one bucket per distinct value) |
| `direction` | `inbound` or `outbound`; omit for both |
| `window` | Go duration (`1h`, `10m`, `30s`); default `1h` |
| `messages` | whole-message budget (a message to several recipients in one domain counts once per domain) |
| `recipients` | RCPT budget (each recipient counts) |

Recipient dimensions are enforced at `RCPT`/`DATA` on both port 25 and
submission; sender and IP dimensions likewise. A denied transaction gets
`452` and is logged with the dimension that tripped. An invalid rule is a
startup warning, not a fatal error.

---

## Outbound IP rotation

A server with several public IPs — or several NAT'd addresses inside an
LXD container — can spread its outbound mail across them and build
per-IP reputation. With no `egress.addresses` the server sends from the
OS default source and `server.hostname`.

```yaml
egress:
  strategy: recipient_domain    # recipient_domain | sender_domain | round_robin
  addresses:
    - address: 203.0.113.10     # public IP: its PTR, and in every domain's SPF
      helo: mail1.example.com   # EHLO name; should match this IP's reverse DNS
      bind: 10.1.0.20           # local IP to bind (see LXD below); omit on a plain host
    - address: 203.0.113.11
      helo: mail2.example.com
      bind: 10.1.0.21
      domains: [clientea.com]   # only for strategy: sender_domain
```

**Strategies**

| Strategy | Behaviour |
|---|---|
| `recipient_domain` (default) | the same destination domain always leaves from the same IP (sticky by hash) — best for reputation and warm-up |
| `sender_domain` | each hosted domain leaves from its mapped IP (`domains:`); keeps tenants' reputations separate |
| `round_robin` | the next IP in sequence, per message |

**On a plain host** each public IP is bound directly — leave `bind`
empty (it defaults to `address`).

**Inside an LXD container** the container does not hold the public IPs;
the host does, and NATs each one to an internal bridge address. So set
`bind` to the **internal** address (what verta binds) and `address` to
the **public** IP (what the world sees, used for the EHLO/PTR/SPF). On
the host, one SNAT rule per pair, e.g.:

```sh
# host: map each internal container IP to its public IP for outbound 25
iptables -t nat -A POSTROUTING -s 10.1.0.20 -p tcp --dport 25 -j SNAT --to-source 203.0.113.10
iptables -t nat -A POSTROUTING -s 10.1.0.21 -p tcp --dport 25 -j SNAT --to-source 203.0.113.11
```

**Deliverability.** For each IP: publish a **PTR** matching its `helo`,
and add the IP to **every hosted domain's SPF**
(`v=spf1 ip4:203.0.113.10 ip4:203.0.113.11 -all`). Forwarded mail uses
[SRS](#aliases-forwarding-and-filters), so the SPF that matters at the
destination is the forwarding domain's — list these IPs there too.

Changing the pool takes effect on restart.

---

## Reputation and warm-up

```yaml
reputation:
  enabled: true
  file: /var/lib/verta/reputation.json
  warmup:
    enabled: true
    day1: 100
    day7: 2000
    full_per_day: 50000
```

Every local sender and domain carries a score from 0 to 100, starting
at 50. Successful deliveries and passing authentication raise it;
bounces, spam complaints, blacklist appearances and anomalous sending
lower it. Scores **decay back toward 50** over time, so an old
incident does not haunt a sender forever and a long-quiet good sender
does not keep a reputation it no longer earns.

A sender whose score collapses is refused with `450` until it
recovers.

Warm-up ramps a new domain's daily allowance along the configured
curve over 30 days. Sending 50 000 messages on day one from a fresh
domain is the fastest way to get an IP blocked; the ramp makes that
impossible by construction.

---

## Administrative API

```yaml
api:
  enabled: true
  address: ":8443"
  keys:
    - "0123456789abcdef0123456789abcdef0123456789abcdef"
```

HTTPS with **static API keys only** — no JWT, no sessions, no refresh
flow. Enabling the API without keys is a startup error, and the
listener does not start without a certificate.

```
GET  /health              liveness, the only unauthenticated endpoint
GET  /api/v1/status       version, uptime, domain/user counts, queue depth
GET  /api/v1/domains      hosted domains
GET  /api/v1/users        mailboxes (never any password material)
GET  /api/v1/reputation   sender scores, worst first
POST /api/v1/reload       re-read the configuration
```

```sh
curl -H "Authorization: Bearer $KEY" https://mail.example.com:8443/api/v1/status
```

`X-API-Key` is accepted as an alternative header. Keys are compared in
constant time, and authentication attempts are rate limited per source
IP so the API cannot be used as a key-guessing oracle. Generate keys
with `openssl rand -hex 32`.

---

## Running in a container

```yaml
container:
  enabled: true
  type: lxd
  public_ip: "203.0.113.10"
  internal_ip: "10.1.0.20"
```

From the outside, a containerized verta is indistinguishable from one
installed on the metal. The SMTP banner, the EHLO name, the trace
headers and even the Maildir file names carry `server.hostname` and
`public_ip` — never the container's own name, never an address from
the internal bridge:

```
220 mail.example.com ESMTP Verta          correct
220 container01.lxd ESMTP Verta           never
```

A source address on the internal network — a webmail submitting
through verta is the common case — is recorded in outgoing trace
headers as the public IP, so relayed mail never carries your private
topology. Public sender addresses are preserved: the real origin of
inbound mail stays traceable.

Storage works with an internal Maildir, an LXD bind mount or a ZFS
dataset; point the mailbox paths wherever the volume is mounted.

Verify the whole thing with `verta --container-check`.

**Backups are not verta's job.** Snapshot the mail storage, the queue
and the DKIM keys with LXD or ZFS snapshots, and keep a copy of
`/etc/verta`.

---

## Logging

```yaml
log:
  dir: /var/log/verta
```

One JSON object per line:

```json
{"time":"2026-07-18T10:14:06Z","level":"WARN","msg":"relay denied",
 "event":"relay_denied","protocol":"smtp","ip":"203.0.113.99",
 "from":"a@b.org","rcpt":"victim@external.org","action":"reject"}
```

Security-relevant events carry a stable `event` field:
`relay_denied`, `auth_failed`, `auth_locked`, `sender_mismatch`,
`ratelimit`, `ratelimit_out`, `reputation_block`, `blacklist_hit`,
`policy_reject`, `policy_quarantine`, `spam_score`, `mail_auth`,
`message_in`, `message_submitted`, `message_out`, `bounce`.

Rotation is delegated to logrotate; `SIGHUP` reopens the files.

---

## Status

`verta --status` asks the running daemon what it is doing:

```
verta v0.3.0  mail.example.com
  pid 2841, up 6d3h12m

Listeners
  smtp         :25
  submission   :587
  imaps        :993

TLS
  example.com, studenti.ente.it

Domains (2, 34 mailboxes)
  example.com                    virtual       28 mailbox(es)  dkim
  studenti.ente.it               virtual        6 mailbox(es)  unsigned

Mail since start
  inbound     18422 received, 91 rejected, 1204 spam, 3317 relay denied
  submission  2210 accepted, 2214 auth ok, 63 auth failed
  outbound    2198 delivered, 9 deferred, 3 bounced
  queue       9 waiting
```

It reads a unix socket at `/run/verta/verta.sock`, so it needs no
credentials and cannot be reached from another machine — the
administrative API remains the remote interface. `--json` gives the
same data for scripts. A failed reload and any configuration warning
are reported here too, so a half-applied change is visible without
reading the log.

## Diagnostics

```sh
verta --audit            local configuration and permissions, no network
verta --security-check   probe the live deployment
verta --container-check  verify a containerized deployment's identity
```

**`audit`** inspects only this machine, so it is safe to run anywhere:
configuration posture, credentials, and file permissions — including
that DKIM private keys are not readable beyond their owner.

**`security-check`** exercises the running server: an actual
open-relay attempt (reading the configuration is not evidence, a `554`
is), `AUTH` refused on port 25, `VRFY`/`EXPN` disabled, TLS
certificates and expiry, MX/SPF/DKIM/DMARC per domain with the
published DKIM key compared to the local one, forward-confirmed
reverse DNS, and the blacklist status of your sending IP. Use
`--host` to probe an address other than `server.hostname`, which is
what you want during installation.

**`container-check`** verifies the public identity end to end,
including a worked example of the address substitution.

All three exit `1` when a check fails — warnings alone do not — so
they drop into monitoring as they are.

---

## Command reference

The service verbs are bare words; every other action is a `--flag`, so
a diagnostic or a one-shot task can never be taken for a service
command.

```
Service (bare):
  verta start [--config p]      run in the foreground (what systemd does)
  verta stop                    signal the running daemon to shut down
  verta reload                  reload config, domains and certificates
  verta restart                 stop the running daemon, then start again

Setup (--flags):
  verta --init                    install the binary, create the layout
  verta --purge [--yes]           remove config, domains, logs and state

Everything else (--flags):
  verta --status [--json]         query the running daemon
  verta --check-config            validate and summarise, then exit
  verta --hash-password           read a password, print an argon2id hash
  verta --generate-dkim <domain>  create a signing key, print the DNS record
  verta --audit                   inspect the local config, no network
  verta --security-check [--host a] probe the live deployment
  verta --container-check         verify a containerized deployment
  verta --version                 print version and exit
```

Getting the dash convention wrong is reported with a hint: `verta init`
tells you to use `--init`, and `verta --start` tells you to drop the
dashes.

---

## DNS records

```dns
; MX — mail for the domain arrives here
example.com.                    IN MX    10 mail.example.com.
mail.example.com.               IN A     203.0.113.10

; SPF — who may send as this domain
example.com.                    IN TXT   "v=spf1 mx -all"

; DKIM — printed by: verta --generate-dkim example.com
default._domainkey.example.com. IN TXT   "v=DKIM1; k=rsa; p=MIIBIjANBg..."

; DMARC — what receivers should do when the above fail
_dmarc.example.com.             IN TXT   "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com"
```

The PTR record of the public IP must resolve to `server.hostname`, and
that name must resolve back to the same address. Large receivers check
this before accepting anything; `verta --security-check` verifies it.

---

## Building

Go 1.26 or newer.

```sh
make            # bin/verta          (linux/amd64, static)
make release    # + bin/verta-arm64  (linux/arm64, static)
make test       # go test ./... -race
make install    # install binary, config skeleton and unit
```

Releases are built by CI from a tag, after the full suite passes, and
published with the systemd unit, a sample configuration and
`SHA256SUMS`.

---

## Project status

Feature-complete against the original specification: SMTP with
structural anti-relay, authenticated submission, IMAP and POP3,
SPF/DKIM/DMARC, spam and virus filtering, blacklists, rate limiting,
reputation with warm-up, the administrative API, container identity
and the diagnostic commands. Recipient routing adds aliases,
distribution lists, catch-all, forwarding with SRS, and per-mailbox
delivery filters.

Deliberately not implemented yet: Prometheus metrics, ARC (RFC 8617),
OAuth2, and Linux user authentication via PAM.

## License

See [LICENSE](LICENSE).
