package queue

import (
	"sync"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/pace"
)

// recTransport records deliveries and always succeeds.
type recTransport struct {
	mu        sync.Mutex
	delivered []string
}

func (r *recTransport) Deliver(e *Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delivered = append(r.delivered, e.Rcpt)
	return nil
}

func (r *recTransport) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.delivered)
}

// With a "1 per 5s to gmail" throttle, two due gmail messages must not
// both go out in one pass: the first is delivered, the second is held in
// the queue with a NextAttempt about five seconds out — no bounce, no
// wasted attempt.
func TestSchedulerPacesPerDomain(t *testing.T) {
	q, _ := Open(t.TempDir())
	q.Enqueue("a@here.it", "x@gmail.com", []byte("m1"))
	q.Enqueue("a@here.it", "y@gmail.com", []byte("m2"))

	tr := &recTransport{}
	s := NewScheduler(q, tr, func(*Envelope, string) { t.Error("no bounce expected") }, 10, quietLog())
	s.SetThrottle(pace.New([]pace.Rule{
		{Match: "gmail.com", Limit: pace.Limit{Rate: 0.2, Burst: 1}},
	}))

	now := time.Now()
	s.Process(now)

	if tr.count() != 1 {
		t.Fatalf("exactly one message should go out this pass, got %d", tr.count())
	}
	if q.Size() != 1 {
		t.Fatalf("the paced message should still be queued, size=%d", q.Size())
	}
	e, ok := q.Earliest(now)
	if !ok || !e.After(now) {
		t.Fatalf("held message should have a future NextAttempt: %v %v", e, ok)
	}
	if d := e.Sub(now); d < 4*time.Second || d > 6*time.Second {
		t.Errorf("held message should come due in ~5s, got %v", d)
	}

	// The attempt count must be untouched: pacing is not a failure.
	due, _ := q.Due(e.Add(time.Second))
	if len(due) != 1 || due[0].Attempts != 0 {
		t.Errorf("paced envelope must keep attempts at 0: %+v", due)
	}
}

// A domain with no matching rule is not paced.
func TestSchedulerUnthrottledDomain(t *testing.T) {
	q, _ := Open(t.TempDir())
	q.Enqueue("a@here.it", "x@fast.com", []byte("m1"))
	q.Enqueue("a@here.it", "y@fast.com", []byte("m2"))

	tr := &recTransport{}
	s := NewScheduler(q, tr, func(*Envelope, string) { t.Error("no bounce") }, 10, quietLog())
	s.SetThrottle(pace.New([]pace.Rule{{Match: "gmail.com", Limit: pace.Limit{Rate: 0.2, Burst: 1}}}))

	s.Process(time.Now())
	if tr.count() != 2 {
		t.Errorf("fast.com is unthrottled: both should deliver, got %d", tr.count())
	}
	if q.Size() != 0 {
		t.Errorf("queue should be empty, size=%d", q.Size())
	}
}
