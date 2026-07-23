package imap

// IMAP QUOTA (RFC 2087). Verta exposes one quota root per account, named
// "" and covering every folder, so a client (Thunderbird's usage bar,
// for one) can show how full the mailbox is. Limits are managed by the
// server configuration; SETQUOTA is refused.

// cmdGetQuotaRoot answers GETQUOTAROOT <mailbox>: the mailbox's quota
// roots, followed by each root's usage.
func (s *session) cmdGetQuotaRoot(tag string, p *parser) {
	s.requireAuth(tag, func() {
		nameTok, err := p.next()
		if err != nil {
			s.out("%s BAD GETQUOTAROOT needs a mailbox", tag)
			return
		}
		s.out(`* QUOTAROOT %s ""`, quote(nameTok.str))
		s.writeQuota()
		s.out("%s OK GETQUOTAROOT completed", tag)
	})
}

// cmdGetQuota answers GETQUOTA <root>. Only the "" root exists.
func (s *session) cmdGetQuota(tag string, p *parser) {
	s.requireAuth(tag, func() {
		if _, err := p.next(); err != nil {
			s.out("%s BAD GETQUOTA needs a quota root", tag)
			return
		}
		s.writeQuota()
		s.out("%s OK GETQUOTA completed", tag)
	})
}

// writeQuota emits the untagged QUOTA line for the account's single root.
// STORAGE is in kibibytes (RFC 2087); with no limit configured the
// resource list is empty, which clients read as "unlimited".
func (s *session) writeQuota() {
	if s.srv.backend.Quota == nil {
		s.out(`* QUOTA "" ()`)
		return
	}
	used, limit := s.srv.backend.Quota(s.user)
	if limit <= 0 {
		s.out(`* QUOTA "" ()`)
		return
	}
	s.out(`* QUOTA "" (STORAGE %d %d)`, kib(used), kib(limit))
}

// kib rounds a byte count up to whole kibibytes, so a non-empty mailbox
// never reports 0 used.
func kib(b int64) int64 {
	if b < 0 {
		return 0
	}
	return (b + 1023) / 1024
}
