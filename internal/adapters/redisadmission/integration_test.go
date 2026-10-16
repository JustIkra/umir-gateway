//go:build integration

package redisadmission

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/admission"
	"github.com/JustIkra/umir-gateway/internal/admission/contract"
	"github.com/JustIkra/umir-gateway/tests/testsupport/itest"
	"github.com/redis/go-redis/v9"
)

func open(t *testing.T, mutate func(*Config)) (*Adapter, string) {
	t.Helper()
	prefix := itest.RedisPrefix(t)
	cfg := Config{URL: itest.RedisLimiterURL(t), Timeout: 2 * time.Second, Generation: "gen-1", StrictWindow: 600 * time.Millisecond, KeyRoot: prefix, ClientName: "gateway-itest"}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return a, prefix
}

func realTime() contract.Env { return contract.Env{Advance: time.Sleep} }

func TestContractLimiterOnRedis(t *testing.T) {
	contract.Limiter(t, func(t *testing.T) (admission.Limiter, contract.Env) {
		a, _ := open(t, nil)
		return a.Limiter(), realTime()
	})
}

func TestContractSlotsOnRedis(t *testing.T) {
	contract.Slots(t, func(t *testing.T) (admission.Slots, contract.Env) {
		a, _ := open(t, nil)
		return a.Slots(), realTime()
	})
}

func TestContractLeaderOnRedis(t *testing.T) {
	contract.Leader(t, func(t *testing.T) (admission.Leader, contract.Env) {
		a, _ := open(t, nil)
		return a.Leader(), realTime()
	})
}

func TestStalledRedisIsUnavailableNeverAllowed(t *testing.T) {
	target, err := url.Parse(itest.RedisLimiterURL(t))
	if err != nil {
		t.Fatal("invalid Redis URL")
	}
	proxy := itest.NewTCPProxy(t, target.Host)
	target.Host = proxy.Addr()
	a, _ := open(t, func(c *Config) { c.URL, c.Timeout = target.String(), 150*time.Millisecond })
	proxy.Pause()
	d, err := a.Limiter().Admit(context.Background(), admission.Request{ID: "x", Fingerprint: "y", Policy: "p", Dimensions: []admission.Dimension{{Key: "k", Limit: 1, Window: time.Second}}})
	if err == nil || d.Allowed || !IsUnavailable(err) {
		t.Fatalf("a stalled Redis must be unavailable, never allowed: %+v %v", d, err)
	}
	if _, err := a.Slots().Acquire(context.Background(), admission.SlotRequest{Holder: "h", TTL: time.Second, Limits: []admission.SlotLimit{{Key: "sse:k", Max: 1}}}); !IsUnavailable(err) {
		t.Fatalf("slots: %v", err)
	}
	if _, err := a.Continuity().Check(context.Background()); !IsUnavailable(err) {
		t.Fatalf("continuity: %v", err)
	}
	proxy.Resume()
	if err := a.Ping(context.Background()); err != nil {
		t.Fatalf("the pool must recover after the stall: %v", err)
	}
}

func rawClient(t *testing.T) *redis.Client {
	t.Helper()
	opts, err := redis.ParseURL(itest.RedisLimiterURL(t))
	if err != nil {
		t.Fatal("invalid Redis URL")
	}
	c := redis.NewClient(opts)
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return c
}

func TestContinuityMarkerDrivesStrictMode(t *testing.T) {
	a, prefix := open(t, nil)
	raw := rawClient(t)
	marker := prefix + "umir:limiter:generation"
	check := func() admission.State {
		t.Helper()
		s, err := a.Continuity().Check(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if s := check(); s.Mode != admission.Strict || s.Reason != "marker_missing" {
		t.Fatalf("no marker: %+v", s)
	}
	if err := raw.Set(context.Background(), marker, "gen-1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if s := check(); s.Mode != admission.Normal {
		t.Fatalf("matching marker: %+v", s)
	}
	if err := raw.Set(context.Background(), marker, "gen-other", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if s := check(); s.Mode != admission.Strict || s.Reason != "marker_mismatch" {
		t.Fatalf("foreign marker: %+v", s)
	}
	if got := raw.Get(context.Background(), marker).Val(); got != "gen-other" {
		t.Fatalf("a foreign marker must never be overwritten: %q", got)
	}
	// The marker vanishes while running: strict from a shared moment, restored after the strict window.
	if err := raw.Del(context.Background(), marker).Err(); err != nil {
		t.Fatal(err)
	}
	if s := check(); s.Mode != admission.Strict {
		t.Fatalf("lost marker: %+v", s)
	}
	time.Sleep(800 * time.Millisecond)
	if s := check(); s.Mode != admission.Normal {
		t.Fatalf("after the strict window: %+v", s)
	}
	if got := raw.Get(context.Background(), marker).Val(); got != "gen-1" {
		t.Fatalf("the marker must be restored with the configured value: %q", got)
	}
	if n := raw.Exists(context.Background(), prefix+"umir:limiter:strict_since").Val(); n != 0 {
		t.Fatal("strict_since must be removed with the restoration")
	}
}
