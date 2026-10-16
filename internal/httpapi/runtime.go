package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/journal"
)

// RuntimeAuth is what the runtime needs from Auth. Registry reads at the moment of the call;
// SharedRegistry lets a burst of callers share one read that may have started earlier, and reports its
// sequence; RegistryAfter shares a read that started after a ReadMark.
type RuntimeAuth interface {
	ControlToken(context.Context, string) (ServiceClaims, error)
	Registry(context.Context) (expiration.Registry, error)
	ReadMark() uint64
	SharedRegistry(context.Context) (expiration.Registry, uint64, error)
	RegistryAfter(context.Context, uint64) (expiration.Registry, error)
	RegistrySnapshot() (expiration.Registry, bool)
	RegistrySnapshotWithin(time.Duration) (expiration.Registry, bool)
}

// registrationSnapshotAge is how old a registry snapshot may be to answer a registration without a read.
const registrationSnapshotAge = 2 * time.Second

type RuntimeOptions struct {
	Auth                             RuntimeAuth
	ServiceKey, Epoch, TZDataVersion string
	Changes                          *journal.Scoped
}
type runtimeEntry struct {
	version   int64
	operation string
	closed    bool
}
type GatewayRuntime struct {
	opts    RuntimeOptions
	mu      sync.Mutex
	entries map[string]runtimeEntry
}

func NewGatewayRuntime(opts RuntimeOptions) (*GatewayRuntime, error) {
	if opts.Auth == nil || opts.ServiceKey == "" || opts.Epoch == "" || opts.TZDataVersion == "" || opts.Changes == nil {
		return nil, errors.New("gateway runtime dependencies required")
	}
	return &GatewayRuntime{opts: opts, entries: map[string]runtimeEntry{}}, nil
}
func (g *GatewayRuntime) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	keys := r.Header.Values("X-Umir-Service-Key")
	if len(keys) != 1 || subtle.ConstantTimeCompare([]byte(keys[0]), []byte(g.opts.ServiceKey)) != 1 {
		runtimeFailure(w, 401, "Unauthenticated", "not_committed")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		runtimeFailure(w, 400, "InvalidArgument", "not_committed")
		return
	}
	if r.URL.Path == "/internal/gateway/v2/runtime" {
		if r.Method != http.MethodGet {
			runtimeFailure(w, 405, "InvalidArgument", "not_committed")
			return
		}
		runtimeJSON(w, struct {
			Service string `json:"service"`
			Epoch   string `json:"epoch"`
			Ready   bool   `json:"ready"`
			TZData  string `json:"tzdataVersion"`
		}{"gateway", g.opts.Epoch, g.ready(), g.opts.TZDataVersion})
		return
	}
	prefix := "/internal/gateway/v2/r/"
	if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, "/registry") || (r.Method != http.MethodPut && r.Method != http.MethodDelete) {
		runtimeFailure(w, 404, "NotFound", "not_committed")
		return
	}
	tenant := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/registry")
	tenantData, err := json.Marshal(tenant)
	if err != nil || ValidateScopeWire("EntityID", tenantData) != nil {
		runtimeFailure(w, 400, "InvalidArgument", "not_committed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tokens := r.Header.Values("Authorization")
	if len(tokens) != 1 || !strings.HasPrefix(tokens[0], "Bearer ") {
		runtimeFailure(w, 401, "InvalidToken", "not_committed")
		return
	}
	claims, err := g.opts.Auth.ControlToken(ctx, strings.TrimPrefix(tokens[0], "Bearer "))
	if err != nil {
		var failure *ScopeError
		if errors.As(err, &failure) {
			runtimeFailure(w, failure.Status, failure.Code, failure.Outcome)
		} else {
			runtimeFailure(w, 503, "AuthUnavailable", "unavailable")
		}
		return
	}
	operation := "runtime.register"
	schema := "RegisterRuntime"
	if r.Method == http.MethodDelete {
		operation = "runtime.close"
		schema = "CloseRuntime"
	}
	if claims.Kind != "service" || claims.Subject != "service:auth" || claims.Caller != "umir-auth" || claims.TenantID != tenant || claims.Operation != operation || !slices.Equal(claims.Audience, []string{"umir-gateway"}) || !slices.Equal(claims.Permissions, []string{operation}) {
		runtimeFailure(w, 403, "Forbidden", "not_committed")
		return
	}
	if claims.Epoch != g.opts.Epoch {
		runtimeFailure(w, 409, "RuntimeReset", "indeterminate")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || len(data) > 8192 || ValidateScopeWire(schema, data) != nil {
		runtimeFailure(w, 400, "InvalidArgument", "not_committed")
		return
	}
	var input struct {
		OperationID   string `json:"operationID"`
		ExpectedEpoch string `json:"expectedEpoch"`
		Version       string `json:"lifecycleVersion"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		runtimeFailure(w, 400, "InvalidArgument", "not_committed")
		return
	}
	if input.ExpectedEpoch != g.opts.Epoch {
		runtimeFailure(w, 409, "RuntimeReset", "indeterminate")
		return
	}
	if input.Version != claims.LifecycleVersion {
		runtimeFailure(w, 403, "Forbidden", "not_committed")
		return
	}
	if operation == "runtime.register" {
		var settings struct {
			Settings ScopeSettings `json:"settings"`
		}
		if err := json.Unmarshal(data, &settings); err != nil {
			runtimeFailure(w, 400, "InvalidArgument", "not_committed")
			return
		}
		if verdict := g.checkRegistration(ctx, tenant, settings.Settings, claims.OrgID, input.Version); verdict.status != 0 {
			runtimeFailure(w, verdict.status, verdict.code, verdict.outcome)
			return
		}
		if _, err := time.LoadLocation(settings.Settings.TimeZone); err != nil {
			runtimeFailure(w, 503, "TimeZoneDataUnavailable", "unavailable")
			return
		}
	}
	version, err := strconv.ParseInt(input.Version, 10, 64)
	if err != nil {
		runtimeFailure(w, 400, "InvalidArgument", "not_committed")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	previous, exists := g.entries[tenant]
	if exists && (version < previous.version || previous.closed && operation == "runtime.register") {
		runtimeFailure(w, 410, "ScopeDeleted", "not_committed")
		return
	}
	if exists && version == previous.version && input.OperationID != previous.operation {
		runtimeFailure(w, 409, "CommandConflict", "not_committed")
		return
	}
	if !exists && len(g.entries) >= 10000 {
		runtimeFailure(w, 503, "ServiceUnavailable", "unavailable")
		return
	}
	closed := operation == "runtime.close"
	if closed && (!exists || !previous.closed) {
		if err := g.opts.Changes.CloseScope(tenant); err != nil {
			runtimeFailure(w, 503, "ServiceUnavailable", "unavailable")
			return
		}
	}
	g.entries[tenant] = runtimeEntry{version: version, operation: input.OperationID, closed: closed}
	state := "ready"
	if closed {
		state = "closed"
	}
	runtimeJSON(w, struct {
		RestaurantID string `json:"restaurantID"`
		Service      string `json:"service"`
		Epoch        string `json:"epoch"`
		State        string `json:"state"`
		Version      string `json:"lifecycleVersion"`
	}{tenant, "gateway", g.opts.Epoch, state, input.Version})
}

// registrationVerdict is the outcome of checking a registration against the registry; status 0
// accepts it.
type registrationVerdict struct {
	status        int
	code, outcome string
}

func (v registrationVerdict) divergent() bool { return v.status == 409 || v.status == 410 }

// checkRegistration compares a registration with the Auth registry. It answers from a snapshot that is
// young enough and holds the restaurant, otherwise from one shared read. A snapshot or shared read may
// predate the change Auth is registering, so a verdict that would refuse with 409 or 410 is confirmed
// by a read that started after the request arrived before it is given.
func (g *GatewayRuntime) checkRegistration(ctx context.Context, tenant string, settings ScopeSettings, orgID, version string) registrationVerdict {
	unavailable := registrationVerdict{503, "AuthUnavailable", "unavailable"}
	mark := g.opts.Auth.ReadMark()
	registry, ok := g.opts.Auth.RegistrySnapshotWithin(registrationSnapshotAge)
	// fresh: the answer comes from a read that started after this request arrived.
	fresh := false
	if !ok || !registry.Complete || !registryHolds(registry, tenant) {
		var (
			sequence uint64
			err      error
		)
		if registry, sequence, err = g.opts.Auth.SharedRegistry(ctx); err != nil || !registry.Complete {
			return unavailable
		}
		fresh = sequence > mark
	}
	verdict := judgeRegistration(registry, tenant, settings, orgID, version)
	if !verdict.divergent() || fresh {
		return verdict
	}
	registry, err := g.opts.Auth.RegistryAfter(ctx, mark)
	if err != nil || !registry.Complete {
		return unavailable
	}
	return judgeRegistration(registry, tenant, settings, orgID, version)
}

func registryHolds(registry expiration.Registry, tenant string) bool {
	return slices.ContainsFunc(registry.Entries, func(e expiration.RegistryEntry) bool { return e.Restaurant.RestaurantID == tenant }) ||
		slices.ContainsFunc(registry.Tombstones, func(t expiration.Tombstone) bool { return t.RestaurantID == tenant })
}

func judgeRegistration(registry expiration.Registry, tenant string, settings ScopeSettings, orgID, version string) registrationVerdict {
	deleted := registrationVerdict{410, "ScopeDeleted", "not_committed"}
	for _, t := range registry.Tombstones {
		if t.RestaurantID == tenant {
			return deleted
		}
	}
	found := false
	for _, e := range registry.Entries {
		if e.Restaurant.RestaurantID != tenant {
			continue
		}
		if found {
			return registrationVerdict{503, "AuthUnavailable", "unavailable"}
		}
		found = true
		if e.Settings.TimeZone != settings.TimeZone || e.Settings.Version != settings.SettingsVersion {
			return registrationVerdict{409, "SettingsChanged", "not_committed"}
		}
		if e.Restaurant.Lifecycle == "deleting" || e.Restaurant.Lifecycle == "deleted" || e.Restaurant.LifecycleVersion != version || e.Restaurant.OrgID != orgID {
			return deleted
		}
	}
	if !found {
		return deleted
	}
	return registrationVerdict{}
}

func (g *GatewayRuntime) ready() bool {
	registry, current := g.opts.Auth.RegistrySnapshot()
	if !current || !registry.Complete {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, entry := range registry.Entries {
		local, ok := g.entries[entry.Restaurant.RestaurantID]
		if !ok {
			return false
		}
		if entry.Restaurant.Lifecycle == "deleting" || entry.Restaurant.Lifecycle == "deleted" {
			if !local.closed {
				return false
			}
			continue
		}
		if local.closed || strconv.FormatInt(local.version, 10) != entry.Restaurant.LifecycleVersion {
			return false
		}
	}
	for _, tombstone := range registry.Tombstones {
		if local, ok := g.entries[tombstone.RestaurantID]; !ok || !local.closed {
			return false
		}
	}
	return true
}
func runtimeFailure(w http.ResponseWriter, status int, code, outcome string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	runtimeJSON(w, struct {
		Code      string `json:"code"`
		Outcome   string `json:"outcome"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	}{code, outcome, "runtime request failed", status == 503})
}
func runtimeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}
