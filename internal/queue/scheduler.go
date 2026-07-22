package queue

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/pace"
)

// PermanentError is a definitive SMTP failure (5xx): no retry, the
// message bounces immediately.
type PermanentError struct {
	Code int
	Msg  string
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("permanent failure %d: %s", e.Code, e.Msg)
}

// Transport delivers one envelope to its destination. A nil return
// means delivered; a *PermanentError bounces; anything else retries.
type Transport interface {
	Deliver(e *Envelope) error
}

// Counters is the subset of stats the scheduler updates. A nil
// pointer disables counting.
type Counters interface {
	IncDelivered()
	IncBounced()
	IncDeferred()
}

// Scheduler drains the queue: due envelopes are delivered, transient
// failures are retried with exponential backoff, permanent failures
// and exhausted retries bounce back to the sender (RFC 3464).
type Scheduler struct {
	q           *Queue
	t           Transport
	bounce      func(e *Envelope, reason string)
	log         *slog.Logger
	maxAttempts int
	interval    time.Duration
	counters    Counters
	throttle    *pace.Throttle
}

// SetCounters wires the status counters.
func (s *Scheduler) SetCounters(c Counters) { s.counters = c }

// SetThrottle wires the outbound pacing (per-destination rate limits).
// nil paces nothing.
func (s *Scheduler) SetThrottle(t *pace.Throttle) { s.throttle = t }

// minWake floors the sleep between passes so pacing a burst of held
// messages cannot spin the loop.
const minWake = 200 * time.Millisecond

func (s *Scheduler) countDelivered() {
	if s.counters != nil {
		s.counters.IncDelivered()
	}
}

func (s *Scheduler) countBounced() {
	if s.counters != nil {
		s.counters.IncBounced()
	}
}

func (s *Scheduler) countDeferred() {
	if s.counters != nil {
		s.counters.IncDeferred()
	}
}

// NewScheduler wires a Scheduler. bounce receives envelopes that
// definitively failed; maxAttempts caps transient retries.
func NewScheduler(q *Queue, t Transport, bounce func(*Envelope, string), maxAttempts int, log *slog.Logger) *Scheduler {
	return &Scheduler{
		q: q, t: t, bounce: bounce, log: log,
		maxAttempts: maxAttempts,
		interval:    30 * time.Second,
	}
}

// Run processes the queue until stop is closed. Between passes it sleeps
// until the next envelope is due (a paced message may be only seconds
// away) or the regular interval elapses, whichever is sooner.
func (s *Scheduler) Run(stop <-chan struct{}) {
	for {
		now := time.Now()
		s.Process(now)

		wake := now.Add(s.interval)
		if e, ok := s.q.Earliest(time.Now()); ok && e.Before(wake) {
			wake = e
		}
		d := time.Until(wake)
		if d < minWake {
			d = minWake
		}
		timer := time.NewTimer(d)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Process attempts every due envelope once. Exported for tests and
// for a future "verta queue flush" command.
func (s *Scheduler) Process(now time.Time) {
	due, errs := s.q.Due(now)
	for _, err := range errs {
		s.log.Error("queue scan error", "error", err.Error())
	}
	for _, e := range due {
		s.attempt(e, now)
	}
}

func (s *Scheduler) attempt(e *Envelope, now time.Time) {
	// Outbound pacing: hold the message if its destination is over its
	// configured rate. This is not a failed attempt — the envelope keeps
	// its attempt count and simply comes due again once a token frees.
	if ok, wait := s.throttle.Reserve(e.Domain); !ok {
		e.NextAttempt = now.Add(wait)
		if uerr := s.q.Update(e); uerr != nil {
			s.log.Error("queue update failed", "queue_id", e.ID, "error", uerr.Error())
		}
		s.log.Info("delivery paced",
			"event", "throttle", "protocol", "smtp",
			"queue_id", e.ID, "domain", e.Domain, "next", e.NextAttempt)
		return
	}

	err := s.t.Deliver(e)
	if err == nil {
		s.countDelivered()
		s.log.Info("message delivered",
			"event", "message_out", "protocol", "smtp",
			"queue_id", e.ID, "from", e.From, "rcpt", e.Rcpt,
			"attempts", e.Attempts+1)
		s.q.Remove(e)
		return
	}

	var perm *PermanentError
	if errors.As(err, &perm) {
		s.countBounced()
		s.log.Warn("delivery failed permanently",
			"event", "bounce", "protocol", "smtp",
			"queue_id", e.ID, "rcpt", e.Rcpt, "error", err.Error())
		s.bounce(e, err.Error())
		s.q.Remove(e)
		return
	}

	e.Attempts++
	e.LastError = err.Error()
	if e.Attempts >= s.maxAttempts {
		s.countBounced()
		s.log.Warn("delivery retries exhausted",
			"event", "bounce", "protocol", "smtp",
			"queue_id", e.ID, "rcpt", e.Rcpt,
			"attempts", e.Attempts, "error", err.Error())
		s.bounce(e, fmt.Sprintf("giving up after %d attempts; last error: %v", e.Attempts, err))
		s.q.Remove(e)
		return
	}
	e.NextAttempt = now.Add(backoff(e.Attempts))
	if uerr := s.q.Update(e); uerr != nil {
		s.log.Error("queue update failed", "queue_id", e.ID, "error", uerr.Error())
	}
	s.countDeferred()
	s.log.Info("delivery deferred",
		"event", "defer", "protocol", "smtp",
		"queue_id", e.ID, "rcpt", e.Rcpt,
		"attempts", e.Attempts, "next", e.NextAttempt, "error", err.Error())
}

// backoff returns the exponential retry delay: 1, 2, 4, 8... minutes,
// capped at 4 hours.
func backoff(attempts int) time.Duration {
	if attempts > 9 {
		attempts = 9 // 1min << 8 = 256 min, already beyond the cap
	}
	d := time.Minute << (attempts - 1)
	if d > 4*time.Hour {
		d = 4 * time.Hour
	}
	return d
}
