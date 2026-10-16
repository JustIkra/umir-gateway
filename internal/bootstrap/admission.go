package bootstrap

import (
	"context"
	"errors"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/redisadmission"
	"github.com/JustIkra/umir-gateway/internal/adapters/redislimiter"
	"github.com/JustIkra/umir-gateway/internal/admission"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/live"
	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

type AdmissionPorts struct {
	Operator   operatorhttp.Admission
	HTTP       httpapi.Admission
	LivePolicy live.LeasePolicy
	LiveSlots  live.Slots
	Close      func() error
}

func OpenAdmission(ctx context.Context, cfg config.Config, getenv func(string) string) (AdmissionPorts, error) {
	redisURL, err := redislimiter.LoadURL(getenv, "GATEWAY", redislimiter.KindLimiter)
	if err != nil {
		return AdmissionPorts{}, err
	}
	durable, err := config.LoadDurable(getenv)
	if err != nil {
		return AdmissionPorts{}, err
	}
	adapter, err := redisadmission.Open(ctx, redisadmission.Config{URL: redisURL, Timeout: cfg.RedisTimeout, Generation: durable.LimiterGeneration, StrictWindow: time.Hour, ClientName: "gateway"})
	if err != nil {
		return AdmissionPorts{}, err
	}
	budgets := make(map[string]admission.Budget, len(cfg.Budgets))
	for name, budget := range cfg.Budgets {
		budgets[name] = admission.Budget{Limit: budget.Limit, Window: budget.Window, Strict: budget.Strict}
	}
	service, err := admission.New(admission.Options{Limiter: adapter.Limiter(), Continuity: adapter.Continuity(), Budgets: budgets, Key: durable.AdmissionKey})
	if err != nil {
		return AdmissionPorts{}, errors.Join(err, adapter.Close())
	}
	ports := AdaptAdmission(service, adapter.Slots())
	ports.Close = adapter.Close
	return ports, nil
}

func AdaptAdmission(service *admission.Service, slots admission.Slots) AdmissionPorts {
	return AdmissionPorts{
		Operator:   operatorAdmission{service},
		HTTP:       httpAdmission{service},
		LivePolicy: liveAdmission{service},
		LiveSlots:  liveSlots{slots},
	}
}

type operatorAdmission struct{ service *admission.Service }

func (a operatorAdmission) Admit(ctx context.Context, rule operatorhttp.AdmissionRule, subjects operatorhttp.AdmissionSubjects, attempt operatorhttp.AdmissionAttempt) (operatorhttp.AdmissionVerdict, error) {
	verdict, err := a.service.Admit(ctx, admission.Rule(rule), admission.Subjects{Client: subjects.Client, Preauth: subjects.Preauth, Global: subjects.Global}, admission.Attempt{ID: attempt.ID, Fingerprint: attempt.Fingerprint})
	if errors.Is(err, admission.ErrConflict) {
		return operatorhttp.AdmissionVerdict{}, operatorhttp.ErrAdmissionConflict
	}
	return operatorhttp.AdmissionVerdict{Allowed: verdict.Allowed, RetryAfter: verdict.RetryAfter}, err
}

type httpAdmission struct{ service *admission.Service }

func (a httpAdmission) Admit(ctx context.Context, rule httpapi.AdmissionRule, subjects httpapi.AdmissionSubjects, attempt httpapi.AdmissionAttempt) (httpapi.AdmissionVerdict, error) {
	verdict, err := a.service.Admit(ctx, admission.Rule(rule), admission.Subjects{Client: subjects.Client, Preauth: subjects.Preauth, User: subjects.User, Restaurant: subjects.Restaurant, Global: subjects.Global}, admission.Attempt{ID: attempt.ID, Fingerprint: attempt.Fingerprint})
	if errors.Is(err, admission.ErrConflict) {
		return httpapi.AdmissionVerdict{}, httpapi.ErrAdmissionConflict
	}
	return httpapi.AdmissionVerdict{Allowed: verdict.Allowed, RetryAfter: verdict.RetryAfter}, err
}

type liveAdmission struct{ service *admission.Service }

func (a liveAdmission) StreamLimits(ctx context.Context, session, org string) ([]live.SlotLimit, error) {
	limits, err := a.service.StreamLimits(ctx, session, org)
	if err != nil {
		return nil, err
	}
	out := make([]live.SlotLimit, 0, len(limits))
	for _, limit := range limits {
		out = append(out, live.SlotLimit{Key: limit.Key, Max: limit.Max})
	}
	return out, nil
}

type liveSlots struct{ slots admission.Slots }

func (s liveSlots) Acquire(ctx context.Context, request live.SlotRequest) (live.SlotGrant, error) {
	converted := admission.SlotRequest{Holder: request.Holder, TTL: request.TTL}
	for _, limit := range request.Limits {
		converted.Limits = append(converted.Limits, admission.SlotLimit{Key: limit.Key, Max: limit.Max})
	}
	grant, err := s.slots.Acquire(ctx, converted)
	return live.SlotGrant{Granted: grant.Granted, Denied: grant.Denied}, err
}

func (s liveSlots) Renew(ctx context.Context, holder string, ttl time.Duration, keys ...string) (bool, error) {
	return s.slots.Renew(ctx, holder, ttl, keys...)
}

func (s liveSlots) Release(ctx context.Context, holder string, keys ...string) error {
	return s.slots.Release(ctx, holder, keys...)
}
