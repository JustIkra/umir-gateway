package live

import "time"

// Clock gives streams their time; tests replace it with a fake one.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer delivers one time on C after its duration unless it is stopped first.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// SystemClock is the process clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) NewTimer(d time.Duration) Timer { return systemTimer{timer: time.NewTimer(d)} }

type systemTimer struct{ timer *time.Timer }

func (t systemTimer) C() <-chan time.Time { return t.timer.C }

func (t systemTimer) Stop() bool { return t.timer.Stop() }
