package operator

import (
	"errors"
	"time"
)

// Defaults of the public feedback form (gateway#10).
const (
	DefaultFeedbackContextLimit = 5
	DefaultFeedbackProcessLimit = 60
	DefaultFeedbackWindow       = 10 * time.Minute
)

// ErrFeedbackRateLimited is wrapped by FeedbackLimitError.
var ErrFeedbackRateLimited = errors.New("feedback rate limited")

// FeedbackLimitError refuses a feedback post while its CSRF context or the whole process has used up
// its posts in the rolling window.
type FeedbackLimitError struct {
	// RetryAfter is a whole number of seconds, at least one.
	RetryAfter time.Duration
}

func (e *FeedbackLimitError) Error() string { return ErrFeedbackRateLimited.Error() }

func (e *FeedbackLimitError) Unwrap() error { return ErrFeedbackRateLimited }

// attempts holds the times of admitted posts in a rolling window; it never grows past its limit.
type attempts struct{ at []time.Time }

// wait forgets posts older than window and returns how long until another post fits under limit, or
// zero when one fits now.
func (a *attempts) wait(now time.Time, limit int, window time.Duration) time.Duration {
	kept := a.at[:0]
	for _, at := range a.at {
		if now.Sub(at) < window {
			kept = append(kept, at)
		}
	}
	a.at = kept
	if len(kept) < limit {
		return 0
	}
	oldest := kept[0]
	for _, at := range kept[1:] {
		if at.Before(oldest) {
			oldest = at
		}
	}
	return oldest.Add(window).Sub(now)
}

// AdmitFeedback admits one post of the public feedback form. csrfToken must be the token of the live
// session sessionID or of the live anonymous context anonymousID; neither is extended. An admitted
// post counts against its context and against the process within FeedbackWindow. A refused post
// counts against nothing, and submitted strings never create state.
func (s *Service) AdmitFeedback(sessionID, anonymousID, csrfToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	var posts *attempts
	if st := s.liveLocked(sessionID, now); st != nil && MatchToken(sessionCSRF(sessionID), csrfToken) {
		posts = &st.feedback
	} else if c, ok := s.anonymous[anonymousID]; ok && s.anonymousLive(c, now) && MatchToken(c.token, csrfToken) {
		posts = &c.feedback
	} else {
		return ErrInvalidCSRFToken
	}
	wait := max(posts.wait(now, s.opts.FeedbackContextLimit, s.opts.FeedbackWindow),
		s.feedback.wait(now, s.opts.FeedbackProcessLimit, s.opts.FeedbackWindow))
	if wait > 0 {
		return &FeedbackLimitError{RetryAfter: wholeSeconds(wait)}
	}
	posts.at = append(posts.at, now)
	s.feedback.at = append(s.feedback.at, now)
	return nil
}
