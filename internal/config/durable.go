package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Live topic modes (C39): every change names all five topics, or the topics of the event.
const (
	TopicsAll   = "all"
	TopicsEvent = "event"
)

// Budget is one admission budget: Limit admissions per fixed Window (a slot count for the SSE leases,
// whose Window is zero). Strict is the limit while the continuity of the limiter is in question (R7).
type Budget struct {
	Limit  int
	Window time.Duration
	Strict int
}

// budgetDefaults are the numbers approved at G1 (docs/durable/admission.md in the factory repository),
// kept here as defaults only: every one can be replaced by GATEWAY_BUDGET_<NAME>=<limit>/<window>.
var budgetDefaults = map[string]Budget{
	"csrf_client":          {60, time.Minute, 20},
	"csrf_global":          {5000, 10 * time.Minute, 1500},
	"login_client":         {20, time.Minute, 5},
	"registration_client":  {10, 10 * time.Minute, 2},
	"registration_preauth": {3, 10 * time.Minute, 1},
	"registration_global":  {300, 10 * time.Minute, 60},
	"reset_client":         {10, 10 * time.Minute, 2},
	"feedback_client":      {20, time.Hour, 4},
	"feedback_preauth":     {5, 10 * time.Minute, 1},
	"feedback_global":      {200, time.Hour, 40},
	"order_user":           {60, time.Minute, 20},
	"order_restaurant":     {600, time.Minute, 200},
	"sse_session":          {8, 0, 4},
	"sse_org":              {200, 0, 50},
	"sse_cell":             {2000, 0, 500},
}

const (
	maxBudgetLimit  = 10_000_000
	maxBudgetWindow = 24 * time.Hour
)

// Bounds of the durable-stack tuning.
const (
	minLiveMaxScopes      = 1
	maxLiveMaxScopes      = 10000
	minLiveRingIdle       = time.Minute
	maxLiveRingIdle       = 24 * time.Hour
	minRegistrySync       = 5 * time.Second
	maxRegistrySync       = 10 * time.Minute
	maxExpirationBatch    = 1000
	minRedisTimeout       = 10 * time.Millisecond
	maxRedisTimeout       = 5 * time.Second
	minSecretLength       = 32
	maxLimiterGenerationN = 256
)

// loadDurableTuning reads the Auth-mode settings of the Redis admission, the live ring and the registry
// projection. It never echoes a value.
func loadDurableTuning(cfg *Config, value func(key, fallback string) string) error {
	var err error
	if cfg.RedisTimeout, err = duration("GATEWAY_REDIS_TIMEOUT", value("GATEWAY_REDIS_TIMEOUT", "200ms")); err != nil || cfg.RedisTimeout < minRedisTimeout || cfg.RedisTimeout > maxRedisTimeout {
		return errors.New("GATEWAY_REDIS_TIMEOUT: expected a duration from 10ms to 5s")
	}
	if cfg.LiveMaxScopes, err = strconv.Atoi(value("GATEWAY_LIVE_MAX_SCOPES", "2000")); err != nil || cfg.LiveMaxScopes < minLiveMaxScopes || cfg.LiveMaxScopes > maxLiveMaxScopes {
		return fmt.Errorf("GATEWAY_LIVE_MAX_SCOPES: expected an integer from %d to %d", minLiveMaxScopes, maxLiveMaxScopes)
	}
	if cfg.LiveRingIdle, err = duration("GATEWAY_LIVE_RING_IDLE", value("GATEWAY_LIVE_RING_IDLE", "10m")); err != nil || cfg.LiveRingIdle < minLiveRingIdle || cfg.LiveRingIdle > maxLiveRingIdle {
		return errors.New("GATEWAY_LIVE_RING_IDLE: expected a duration from 1m to 24h")
	}
	cfg.LiveTopics = value("GATEWAY_LIVE_TOPICS", TopicsAll)
	if cfg.LiveTopics != TopicsAll && cfg.LiveTopics != TopicsEvent {
		return errors.New("GATEWAY_LIVE_TOPICS: expected all or event")
	}
	if cfg.RegistrySyncInterval, err = duration("GATEWAY_REGISTRY_SYNC_INTERVAL", value("GATEWAY_REGISTRY_SYNC_INTERVAL", "30s")); err != nil || cfg.RegistrySyncInterval < minRegistrySync || cfg.RegistrySyncInterval > maxRegistrySync {
		return errors.New("GATEWAY_REGISTRY_SYNC_INTERVAL: expected a duration from 5s to 10m")
	}
	if cfg.ExpirationBatch, err = strconv.Atoi(value("GATEWAY_EXPIRATION_BATCH", "500")); err != nil || cfg.ExpirationBatch < 1 || cfg.ExpirationBatch > maxExpirationBatch {
		return fmt.Errorf("GATEWAY_EXPIRATION_BATCH: expected an integer from 1 to %d", maxExpirationBatch)
	}
	cfg.Budgets = make(map[string]Budget, len(budgetDefaults))
	for name, def := range budgetDefaults {
		budget, err := loadBudget(name, def, value)
		if err != nil {
			return err
		}
		cfg.Budgets[name] = budget
	}
	return nil
}

// loadBudget applies GATEWAY_BUDGET_<NAME> and GATEWAY_BUDGET_<NAME>_STRICT to a default. A strict
// limit above the normal one is lowered to it.
func loadBudget(name string, def Budget, value func(key, fallback string) string) (Budget, error) {
	key := "GATEWAY_BUDGET_" + strings.ToUpper(name)
	budget := def
	if raw := value(key, ""); raw != "" {
		limitText, windowText, hasWindow := strings.Cut(raw, "/")
		limit, err := strconv.Atoi(limitText)
		if err != nil || limit < 1 || limit > maxBudgetLimit {
			return Budget{}, fmt.Errorf("%s: expected <limit>[/<window>] with a limit from 1 to %d", key, maxBudgetLimit)
		}
		budget.Limit = limit
		switch {
		case def.Window == 0 && hasWindow:
			return Budget{}, fmt.Errorf("%s: a lease budget is a plain number", key)
		case def.Window != 0 && !hasWindow:
			return Budget{}, fmt.Errorf("%s: expected <limit>/<window>", key)
		case hasWindow:
			window, err := time.ParseDuration(windowText)
			if err != nil || window < time.Second || window > maxBudgetWindow {
				return Budget{}, fmt.Errorf("%s: expected a window from 1s to 24h", key)
			}
			budget.Window = window
		}
	}
	if raw := value(key+"_STRICT", ""); raw != "" {
		strict, err := strconv.Atoi(raw)
		if err != nil || strict < 1 || strict > maxBudgetLimit {
			return Budget{}, fmt.Errorf("%s_STRICT: expected an integer from 1 to %d", key, maxBudgetLimit)
		}
		budget.Strict = strict
	}
	budget.Strict = min(budget.Strict, budget.Limit)
	return budget, nil
}

// Durable holds what the Auth mode needs besides Config: secrets, never printed, and the limiter
// generation. The broker and Redis URLs are read by their adapters (rabbitmq.LoadURL, redislimiter.LoadURL).
type Durable struct {
	// AdmissionKey is the HMAC key of the subjects of admission records, the same for all replicas.
	AdmissionKey []byte
	// CursorKey encrypts live cursors, the same for all replicas and not the Auth service key.
	CursorKey []byte
	// LimiterGeneration is compared with the marker umir:limiter:generation (R7, C47).
	LimiterGeneration string
}

// LoadDurable reads the files and the generation the Auth mode requires. Neither a value nor a file
// content reaches an error.
func LoadDurable(getenv func(string) string) (Durable, error) {
	var d Durable
	var err error
	if d.AdmissionKey, err = keyFileOnly(getenv, "GATEWAY_ADMISSION_KEY_FILE"); err != nil {
		return Durable{}, err
	}
	if d.CursorKey, err = keyFileOnly(getenv, "GATEWAY_LIVE_CURSOR_KEY_FILE"); err != nil {
		return Durable{}, err
	}
	if string(d.AdmissionKey) == string(d.CursorKey) {
		return Durable{}, errors.New("GATEWAY_LIVE_CURSOR_KEY_FILE: must not repeat GATEWAY_ADMISSION_KEY_FILE")
	}
	d.LimiterGeneration = getenv("GATEWAY_LIMITER_GENERATION")
	if strings.TrimSpace(d.LimiterGeneration) == "" || len(d.LimiterGeneration) > maxLimiterGenerationN {
		return Durable{}, fmt.Errorf("GATEWAY_LIMITER_GENERATION: expected 1 to %d characters", maxLimiterGenerationN)
	}
	return d, nil
}

// keyFileOnly reads a secret that is given by file only.
func keyFileOnly(getenv func(string) string, fileVariable string) ([]byte, error) {
	if getenv(fileVariable) == "" {
		return nil, fmt.Errorf("%s: required", fileVariable)
	}
	value, err := serviceKey(func(key string) string {
		if key == fileVariable {
			return getenv(fileVariable)
		}
		return ""
	}, strings.TrimSuffix(fileVariable, "_FILE"))
	if err != nil {
		return nil, err
	}
	if len(value) < minSecretLength {
		return nil, fmt.Errorf("%s: expected a key of at least %d bytes", fileVariable, minSecretLength)
	}
	return []byte(value), nil
}
