package httpapi

import (
	"context"
	"errors"
	"time"
)

type AdmissionRule string

const (
	AdmissionFeedback AdmissionRule = "feedback"
	AdmissionOrder    AdmissionRule = "order"
)

type AdmissionSubjects struct {
	Client, Preauth, User, Restaurant string
	Global                            bool
}

type AdmissionAttempt struct {
	ID, Fingerprint string
}

type AdmissionVerdict struct {
	Allowed    bool
	RetryAfter time.Duration
}

type Admission interface {
	Admit(context.Context, AdmissionRule, AdmissionSubjects, AdmissionAttempt) (AdmissionVerdict, error)
}

var ErrAdmissionConflict = errors.New("httpapi: admission identity conflict")

func retryAfterSeconds(wait time.Duration) int {
	return max(1, int((wait+time.Second-1)/time.Second))
}
