package admission

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Rule names a protected route group.
type Rule string

// Rules of the Gateway (docs/durable/admission.md).
const (
	RuleCSRF         Rule = "csrf"
	RuleLogin        Rule = "login"
	RuleRegistration Rule = "registration"
	RuleReset        Rule = "reset"
	RuleFeedback     Rule = "feedback"
	RuleOrder        Rule = "order"
)

// Budget is the configuration of one budget (see config.Budget); Window is zero for slot budgets.
type Budget struct {
	Limit  int
	Window time.Duration
	Strict int
}

// Subjects are the raw subjects of one attempt. A dimension whose subject is empty is left out, which is
// how the client dimension stays off without a trusted proxy. Global adds the dimensions without subject.
type Subjects struct {
	Client, Preauth, User, Restaurant string
	Global                            bool
}

// Attempt identifies a repeatable attempt. An empty ID makes every call a new attempt that is charged.
// Fingerprint stands for the content of the request (a digest of its body).
type Attempt struct {
	ID, Fingerprint string
}

// Verdict is the outcome of Admit for a store that answered.
type Verdict struct {
	Allowed    bool
	RetryAfter time.Duration
}

type kind string

const (
	kindClient     kind = "client"
	kindPreauth    kind = "preauth"
	kindUser       kind = "user"
	kindRestaurant kind = "restaurant"
	kindGlobal     kind = "global"
)

type dimensionSpec struct {
	budget string
	kind   kind
}

var ruleDimensions = map[Rule][]dimensionSpec{
	RuleCSRF:         {{"csrf_client", kindClient}, {"csrf_global", kindGlobal}},
	RuleLogin:        {{"login_client", kindClient}},
	RuleRegistration: {{"registration_client", kindClient}, {"registration_preauth", kindPreauth}, {"registration_global", kindGlobal}},
	RuleReset:        {{"reset_client", kindClient}},
	RuleFeedback:     {{"feedback_client", kindClient}, {"feedback_preauth", kindPreauth}, {"feedback_global", kindGlobal}},
	RuleOrder:        {{"order_user", kindUser}, {"order_restaurant", kindRestaurant}},
}

// Slot budgets of the SSE leases.
const (
	budgetSSESession = "sse_session"
	budgetSSEOrg     = "sse_org"
	budgetSSECell    = "sse_cell"
)

// Options configures a Service.
type Options struct {
	Limiter    Limiter
	Continuity Continuity
	// Budgets are the budgets by name; every name the rules use must be present.
	Budgets map[string]Budget
	// Key is the HMAC key of the subjects stored in the limiter.
	Key []byte
	// NewID makes the IDs of attempts without one; nil uses crypto/rand.
	NewID func() string
}

// Service applies the rules to a limiter: it builds the dimensions, hides the subjects behind an HMAC,
// reads the continuity state before every admission and uses the strict limits while it is Strict.
type Service struct {
	opts   Options
	mu     sync.Mutex
	counts map[string]*Counts
}

// Counts are the numbers of one rule: allowed, refused and unavailable.
type Counts struct{ Allowed, Refused, Unavailable uint64 }

// New checks the options and returns a Service.
func New(opts Options) (*Service, error) {
	if opts.Limiter == nil || opts.Continuity == nil || len(opts.Key) < 16 {
		return nil, errors.New("admission: limiter, continuity and an HMAC key of at least 16 bytes are required")
	}
	need := []string{budgetSSESession, budgetSSEOrg, budgetSSECell}
	for _, specs := range ruleDimensions {
		for _, spec := range specs {
			need = append(need, spec.budget)
		}
	}
	for _, name := range need {
		budget, ok := opts.Budgets[name]
		if !ok || budget.Limit < 1 || budget.Strict < 1 || budget.Strict > budget.Limit {
			return nil, errors.New("admission: budget " + name + " is missing or invalid")
		}
	}
	if opts.NewID == nil {
		opts.NewID = func() string { return rand.Text() }
	}
	return &Service{opts: opts, counts: map[string]*Counts{}}, nil
}

func (s *Service) subject(k kind, value string) (string, error) {
	mac := hmac.New(sha256.New, s.opts.Key)
	if _, err := mac.Write([]byte(string(k) + "\x00" + value)); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) note(rule string, f func(*Counts)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.counts[rule]
	if c == nil {
		c = &Counts{}
		s.counts[rule] = c
	}
	f(c)
}

// Snapshot returns the counters per rule, for the structured log; it carries no key and no subject.
func (s *Service) Snapshot() map[string]Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Counts, len(s.counts))
	for rule, c := range s.counts {
		out[rule] = *c
	}
	return out
}

// Mode reports the continuity state; the readiness of the limiter capability uses it.
func (s *Service) Mode(ctx context.Context) (State, error) {
	state, err := s.opts.Continuity.Check(ctx)
	if err != nil {
		return State{}, errors.Join(ErrUnavailable, err)
	}
	return state, nil
}

// Admit charges one attempt of rule. It returns ErrUnavailable when the store gave no verified answer
// and ErrConflict when attempt.ID was used before with another fingerprint; otherwise the verdict.
func (s *Service) Admit(ctx context.Context, rule Rule, subjects Subjects, attempt Attempt) (Verdict, error) {
	specs, ok := ruleDimensions[rule]
	if !ok {
		return Verdict{}, errors.New("admission: unknown rule " + string(rule))
	}
	type chosen struct {
		spec    dimensionSpec
		subject string
	}
	var picked []chosen
	for _, spec := range specs {
		value := ""
		switch spec.kind {
		case kindClient:
			value = subjects.Client
		case kindPreauth:
			value = subjects.Preauth
		case kindUser:
			value = subjects.User
		case kindRestaurant:
			value = subjects.Restaurant
		case kindGlobal:
			if subjects.Global {
				value = "all"
			}
		}
		if value != "" {
			hidden, err := s.subject(spec.kind, value)
			if err != nil {
				return Verdict{}, errors.Join(ErrUnavailable, err)
			}
			picked = append(picked, chosen{spec, hidden})
		}
	}
	if len(picked) == 0 {
		return Verdict{Allowed: true}, nil
	}
	state, err := s.opts.Continuity.Check(ctx)
	if err != nil {
		s.note(string(rule), func(c *Counts) { c.Unavailable++ })
		return Verdict{}, errors.Join(ErrUnavailable, err)
	}
	request := Request{ID: attempt.ID, Fingerprint: attempt.Fingerprint, Policy: string(rule)}
	if request.ID == "" {
		request.ID, request.Fingerprint = s.opts.NewID(), "-"
	}
	fingerprint := request.Fingerprint
	for _, p := range picked {
		budget := s.opts.Budgets[p.spec.budget]
		limit := budget.Limit
		if state.Mode == Strict {
			limit = budget.Strict
		}
		key := p.spec.budget + ":" + budget.Window.String() + ":" + p.subject
		request.Dimensions = append(request.Dimensions, Dimension{Key: key, Limit: limit, Window: budget.Window})
		if rule == RuleRegistration || rule == RuleReset {
			fingerprint += "\x00" + p.spec.budget + "\x00" + budget.Window.String() + "\x00" + strconv.Itoa(budget.Limit)
		} else {
			fingerprint += "\x00" + key + "\x00" + strconv.Itoa(budget.Limit)
		}
	}
	sum := sha256.Sum256([]byte(fingerprint))
	request.Fingerprint = hex.EncodeToString(sum[:])
	decision, err := s.opts.Limiter.Admit(ctx, request)
	switch {
	case errors.Is(err, ErrConflict):
		return Verdict{}, err
	case err != nil:
		s.note(string(rule), func(c *Counts) { c.Unavailable++ })
		return Verdict{}, errors.Join(ErrUnavailable, err)
	case decision.Allowed:
		s.note(string(rule), func(c *Counts) { c.Allowed++ })
		return Verdict{Allowed: true}, nil
	}
	s.note(string(rule), func(c *Counts) { c.Refused++ })
	return Verdict{RetryAfter: decision.RetryAfter}, nil
}

// RetryAfterSeconds rounds a wait up to whole seconds, at least one.
func RetryAfterSeconds(wait time.Duration) int {
	return max(1, int((wait+time.Second-1)/time.Second))
}

// StreamLimits are the slot keys and limits of one SSE stream: session, organization and cell. The
// organization is known only after the first access decision.
func (s *Service) StreamLimits(ctx context.Context, session, org string) ([]SlotLimit, error) {
	state, err := s.Mode(ctx)
	if err != nil {
		return nil, err
	}
	limit := func(name string) int64 {
		budget := s.opts.Budgets[name]
		if state.Mode == Strict {
			return int64(budget.Strict)
		}
		return int64(budget.Limit)
	}
	var limits []SlotLimit
	if session != "" {
		hidden, err := s.subject("session", session)
		if err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		limits = append(limits, SlotLimit{Key: "sse:s:" + hidden, Max: limit(budgetSSESession)})
	}
	if org != "" {
		limits = append(limits, SlotLimit{Key: "sse:o:" + org, Max: limit(budgetSSEOrg)})
	}
	limits = append(limits, SlotLimit{Key: "sse:cell", Max: limit(budgetSSECell)})
	return limits, nil
}
