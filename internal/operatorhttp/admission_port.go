package operatorhttp

import (
	"context"
	"errors"
	"time"
)

type AdmissionRule string

const (
	AdmissionCSRF         AdmissionRule = "csrf"
	AdmissionLogin        AdmissionRule = "login"
	AdmissionRegistration AdmissionRule = "registration"
	AdmissionReset        AdmissionRule = "reset"
)

type AdmissionSubjects struct {
	Client, Preauth string
	Global          bool
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

var ErrAdmissionConflict = errors.New("operatorhttp: admission identity conflict")

func retryAfterSeconds(wait time.Duration) int {
	return max(1, int((wait+time.Second-1)/time.Second))
}
