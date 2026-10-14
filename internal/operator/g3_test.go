package operator

import (
	"sync"
	"testing"
	"time"
)

type revisionNotice struct {
	revision uint64
	idle     time.Time
}

type delayedRevisionObserver struct {
	started, release chan struct{}
	calls            chan revisionNotice
	once             sync.Once
}

func (o *delayedRevisionObserver) SessionExtended(_ string, revision uint64, idle, _ time.Time) {
	first := false
	o.once.Do(func() { first = true })
	if first {
		close(o.started)
		<-o.release
	}
	o.calls <- revisionNotice{revision, idle}
}
func (o *delayedRevisionObserver) SessionEnded(_ string, revision uint64, _ EndReason) {
	o.calls <- revisionNotice{revision: revision}
}

func TestG3ConcurrentCommitsAssignOrderedRevisions(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	observer := &delayedRevisionObserver{started: make(chan struct{}), release: make(chan struct{}), calls: make(chan revisionNotice, 3)}
	f.svc.opts.Observer = observer
	f.clock.Advance(time.Minute)
	done := make(chan error, 1)
	go func() { _, _, err := f.svc.Authenticate(session.ID); done <- err }()
	select {
	case <-observer.started:
	case <-time.After(time.Second):
		t.Fatal("callback not started")
	}
	f.clock.Advance(time.Minute)
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		close(observer.release)
		t.Fatal(err)
	}
	newer := <-observer.calls
	close(observer.release)
	older := <-observer.calls
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if older.revision == 0 || older.revision >= newer.revision || !newer.idle.After(older.idle) {
		t.Fatalf("unordered revisions: older %+v newer %+v", older, newer)
	}
	_, snapshot, err := f.svc.Peek(session.ID)
	if err != nil || snapshot.PublicationRevision != newer.revision {
		t.Fatalf("snapshot revision %d, want %d: %v", snapshot.PublicationRevision, newer.revision, err)
	}
	if err := f.svc.Logout(session.ID); err != nil {
		t.Fatal(err)
	}
	if ended := <-observer.calls; ended.revision <= newer.revision {
		t.Fatalf("terminal revision: %+v", ended)
	}
}
