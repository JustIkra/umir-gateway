package live

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/journal"
	"github.com/JustIkra/umir-gateway/internal/operator"
)

type AccessChecker interface {
	AccessCheck(context.Context, httpapi.AccessCheckRequest) (httpapi.RestaurantAccess, error)
}

type ScopedOptions struct {
	Auth    AccessChecker
	Journal *journal.Scoped
	Clock   Clock
	// PerSession bounds the streams of one session, PerOrg those of one organization and Total those of
	// the process.
	PerSession, PerOrg, Total int
	WriteTimeout              time.Duration
	Logger                    *log.Logger
}

type Handler struct {
	opts    ScopedOptions
	mu      sync.Mutex
	open    map[string]int
	openOrg map[string]int
	total   int
	closing context.Context
	cancel  context.CancelFunc
	done    sync.WaitGroup
}

func NewHandler(opts ScopedOptions) (*Handler, error) {
	if opts.Auth == nil || opts.Journal == nil || opts.Clock == nil || opts.Logger == nil || opts.PerSession <= 0 || opts.PerOrg <= 0 || opts.Total <= 0 || opts.WriteTimeout <= 0 {
		return nil, errors.New("live: scoped dependencies and bounds are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Handler{opts: opts, open: map[string]int{}, openOrg: map[string]int{}, closing: ctx, cancel: cancel}, nil
}

func (h *Handler) Close() {
	h.mu.Lock()
	h.cancel()
	h.mu.Unlock()
	h.done.Wait()
}

func (h *Handler) acquire(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing.Err() != nil || h.total >= h.opts.Total || h.open[key] >= h.opts.PerSession {
		return false
	}
	h.total++
	h.open[key]++
	h.done.Add(1)
	return true
}

func (h *Handler) release(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total--
	h.open[key]--
	if h.open[key] == 0 {
		delete(h.open, key)
	}
	h.done.Done()
}

// acquireOrg takes a slot of the organization the first access decision names. The session and total
// slots are already held; a refusal leaves them to the caller's release.
func (h *Handler) acquireOrg(org string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing.Err() != nil || h.openOrg[org] >= h.opts.PerOrg {
		return false
	}
	h.openOrg[org]++
	return true
}

func (h *Handler) releaseOrg(org string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.openOrg[org]--
	if h.openOrg[org] <= 0 {
		delete(h.openOrg, org)
	}
}

func (h *Handler) check(ctx context.Context, tenant, session, org string) (httpapi.RestaurantAccess, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	access, err := h.opts.Auth.AccessCheck(ctx, httpapi.AccessCheckRequest{SessionToken: session, RestaurantID: tenant, Operation: "live"})
	if err != nil {
		return httpapi.RestaurantAccess{}, err
	}
	data, err := json.Marshal(access)
	if err != nil || httpapi.ValidateScopeWire("RestaurantAccess", data) != nil || access.RestaurantID != tenant || (org != "" && access.OrgID != org) {
		return httpapi.RestaurantAccess{}, &httpapi.ScopeError{Status: 503, Code: "AuthUnavailable", Message: "invalid access decision"}
	}
	return access, nil
}

func scopedEndReason(err error) string {
	var failure *httpapi.ScopeError
	if errors.As(err, &failure) {
		switch failure.Code {
		case "Forbidden":
			return "revoked"
		case "ScopeDeleted":
			return "deleted"
		case "Unauthenticated":
			return "session-expired"
		}
	}
	return "auth-unavailable"
}

func scopedFrame(kind, tenant, epoch, reason string) frame {
	if kind == "access-ended" {
		return event(kind, struct {
			Type   string `json:"type"`
			Tenant string `json:"tenantID"`
			Reason string `json:"reason"`
		}{kind, tenant, reason})
	}
	return event(kind, struct {
		Type   string `json:"type"`
		Tenant string `json:"tenantID"`
		Epoch  string `json:"epoch"`
	}{kind, tenant, epoch})
}

func (h *Handler) ServeScope(w http.ResponseWriter, r *http.Request, tenant, session, handle string) {
	actor := operator.SessionKey(session)
	if !h.acquire(actor) {
		scopedRefusal(w, http.StatusTooManyRequests, "RateLimited", 1)
		return
	}
	defer h.release(actor)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer context.AfterFunc(h.closing, cancel)()
	checkedAt := h.opts.Clock.Now()
	access, err := h.check(ctx, tenant, session, "")
	if err != nil {
		h.refuse(w, err)
		return
	}
	if !h.acquireOrg(access.OrgID) {
		scopedRefusal(w, http.StatusTooManyRequests, "RateLimited", 1)
		return
	}
	defer h.releaseOrg(access.OrgID)
	signals, stop, err := h.opts.Journal.Watch(tenant)
	if err != nil {
		scopedFailure(w, 503, "UpstreamUnavailable")
		return
	}
	defer stop()
	snapshot, err := h.opts.Journal.Read(tenant, actor, handle, 0, 0)
	if err != nil {
		if errors.Is(err, journal.ErrCursor) {
			scopedFailure(w, 403, "Forbidden")
		} else {
			scopedFailure(w, 503, "UpstreamUnavailable")
		}
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	out := &sender{w: w, controller: http.NewResponseController(w), timeout: h.opts.WriteTimeout}
	defer func() {
		if err := out.release(); err != nil && ctx.Err() == nil {
			h.opts.Logger.Print("scoped stream deadline release failed")
		}
	}()
	recheck := h.opts.Clock.NewTimer(max(0, checkedAt.Add(4*time.Second).Sub(h.opts.Clock.Now())))
	defer func() { recheck.Stop() }()
	checkAccess := func() error {
		checkedAt = h.opts.Clock.Now()
		_, err := h.check(ctx, tenant, session, access.OrgID)
		recheck.Stop()
		recheck = h.opts.Clock.NewTimer(max(0, checkedAt.Add(4*time.Second).Sub(h.opts.Clock.Now())))
		return err
	}
	end := func(err error) {
		reason := scopedEndReason(err)
		if reason == "deleted" {
			if err := h.opts.Journal.CloseScope(tenant); err != nil {
				h.opts.Logger.Print("scoped journal close failed")
			}
		}
		out.timeout = min(h.opts.WriteTimeout, time.Second)
		out.send(scopedFrame("access-ended", tenant, "", reason))
	}
	send := func(f frame) bool {
		remaining := checkedAt.Add(4 * time.Second).Sub(h.opts.Clock.Now())
		if ctx.Err() != nil || remaining <= 0 {
			return false
		}
		out.timeout = min(h.opts.WriteTimeout, remaining)
		return out.send(f)
	}
	checkedSend := func(f frame) bool {
		if ctx.Err() != nil {
			return false
		}
		if err := checkAccess(); err != nil {
			if ctx.Err() == nil {
				end(err)
			}
			return false
		}
		return send(f)
	}
	emit := func(snapshot journal.Snapshot) (journal.Snapshot, bool) {
		if snapshot.Closed {
			end(&httpapi.ScopeError{Code: "ScopeDeleted"})
			return snapshot, false
		}
		if snapshot.Refresh {
			return snapshot, checkedSend(scopedFrame("refresh-required", tenant, snapshot.Epoch, ""))
		}
		for _, change := range snapshot.Changes {
			handle, cursorErr := h.opts.Journal.Cursor(tenant, actor, change.Sequence, snapshot.Generation)
			if err := checkAccess(); err != nil {
				if ctx.Err() == nil {
					end(err)
				}
				return snapshot, false
			}
			current, err := h.opts.Journal.Read(tenant, actor, "", change.Sequence-1, snapshot.Generation)
			if err != nil {
				end(err)
				return snapshot, false
			}
			if current.Closed {
				end(&httpapi.ScopeError{Code: "ScopeDeleted"})
				return current, false
			}
			if current.Refresh {
				return current, send(scopedFrame("refresh-required", tenant, current.Epoch, ""))
			}
			if cursorErr != nil {
				end(cursorErr)
				return current, false
			}
			f := event("change", struct {
				Type     string   `json:"type"`
				Tenant   string   `json:"tenantID"`
				Epoch    string   `json:"epoch"`
				Sequence string   `json:"sequence"`
				Topics   []string `json:"topics"`
			}{"change", tenant, snapshot.Epoch, strconv.FormatInt(change.Sequence, 10), change.Topics})
			f.id = handle
			if ctx.Err() != nil || !send(f) {
				return snapshot, false
			}
		}
		return snapshot, true
	}
	if !send(raw("retry: 3000\n\n")) {
		return
	}
	snapshot, ok := emit(snapshot)
	if !ok {
		return
	}
	after, generation := snapshot.Last, snapshot.Generation
	ping := h.opts.Clock.NewTimer(DefaultPing)
	defer func() { ping.Stop() }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			next, err := h.opts.Journal.Read(tenant, actor, "", after, generation)
			if err != nil {
				end(err)
				return
			}
			next, ok := emit(next)
			if !ok {
				return
			}
			after, generation = next.Last, next.Generation
		case <-recheck.C():
			if err := checkAccess(); err != nil {
				if ctx.Err() == nil {
					end(err)
				}
				return
			}
		case <-ping.C():
			if !checkedSend(raw(": ping\n\n")) {
				return
			}
			ping = h.opts.Clock.NewTimer(DefaultPing)
		}
	}
}

func scopedFailure(w http.ResponseWriter, status int, code string) {
	scopedRefusal(w, status, code, 0)
}

func scopedRefusal(w http.ResponseWriter, status int, code string, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	var details *struct {
		RetryAfter int `json:"retryAfterSeconds"`
	}
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		details = &struct {
			RetryAfter int `json:"retryAfterSeconds"`
		}{retryAfter}
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(struct {
		Code      string `json:"code"`
		Outcome   string `json:"outcome"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
		Details   *struct {
			RetryAfter int `json:"retryAfterSeconds"`
		} `json:"details,omitempty"`
	}{code, "unavailable", "live access is unavailable", retryAfter > 0, details}); err != nil {
		return
	}
}

func (h *Handler) refuse(w http.ResponseWriter, err error) {
	var failure *httpapi.ScopeError
	if errors.As(err, &failure) && failure.Status >= 400 && failure.Status <= 599 {
		scopedRefusal(w, failure.Status, failure.Code, failure.RetryAfter)
		return
	}
	scopedFailure(w, 503, "AuthUnavailable")
}
