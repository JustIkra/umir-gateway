package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/authclient"
	"github.com/JustIkra/umir-gateway/internal/adapters/httpupstream"
	"github.com/JustIkra/umir-gateway/internal/adapters/livecursor"
	"github.com/JustIkra/umir-gateway/internal/clientaddr"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/journal"
	"github.com/JustIkra/umir-gateway/internal/live"
	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

// componentEnv carries the injected time and ticker mechanisms of the Auth-mode composition.
type componentEnv struct {
	now       func() time.Time
	newTicker func(time.Duration) (<-chan time.Time, func())
}

func newAuthComponents(cfg config.Config, logger *log.Logger) (components, error) {
	return newAuthComponentsWith(cfg, logger, componentEnv{now: time.Now, newTicker: newTicker})
}

func newAuthComponentsWith(cfg config.Config, logger *log.Logger, env componentEnv) (components, error) {
	transport := &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second}
	client, err := authclient.New(authclient.Options{URL: cfg.AuthURL, ServiceKey: cfg.AuthServiceKey, Timeout: cfg.AuthTimeout, Transport: transport, Now: env.now, MaxAge: cfg.RegistryMaxAge})
	if err != nil {
		return components{}, err
	}
	refresher, err := authclient.NewRegistryRefresher(authclient.RefresherOptions{Client: client, Interval: cfg.RegistryRefreshInterval, NewTicker: env.newTicker, Logger: logger})
	if err != nil {
		return components{}, err
	}
	clients := clientaddr.Resolver{Trusted: cfg.TrustedProxies}
	api, err := operatorhttp.NewRemote(operatorhttp.RemoteOptions{Auth: client, Mode: operatorhttp.CookieMode(cfg.Operator.CookieMode), PublicOrigin: cfg.Operator.PublicOrigin, Logger: logger, Now: time.Now, NewCommandID: rand.Text, Clients: clients})
	if err != nil {
		return components{}, err
	}
	business, err := httpupstream.NewScopedClient(map[string]httpupstream.ScopedTarget{
		"warehouse": {URL: cfg.WarehouseURL, ServiceKey: cfg.WarehouseServiceKey},
		"serving":   {URL: cfg.ServingURL, ServiceKey: cfg.ServingServiceKey},
		"feedback":  {URL: cfg.FeedbackURL, ServiceKey: cfg.FeedbackServiceKey},
	}, transport, cfg.UpstreamTimeout)
	if err != nil {
		return components{}, err
	}
	epoch, err := newGatewayEpoch()
	if err != nil {
		return components{}, err
	}
	codec, err := livecursor.New(cfg.AuthServiceKey)
	if err != nil {
		return components{}, err
	}
	changes, err := journal.NewScoped(epoch, cfg.LiveRingCapacity, 10000, 4096, time.Now, rand.Text, codec)
	if err != nil {
		return components{}, err
	}
	streams, err := live.NewHandler(live.ScopedOptions{Auth: client, Journal: changes, Clock: live.SystemClock{}, PerSession: cfg.LiveMaxStreamsPerSession, PerOrg: cfg.LiveMaxStreamsPerOrg, Total: cfg.LiveMaxStreams, WriteTimeout: live.DefaultWriteTimeout, Logger: logger})
	if err != nil {
		return components{}, err
	}
	scoped, err := httpapi.NewScoped(httpapi.ScopedOptions{Live: streams, Changes: changes, Auth: client, Business: business, Origin: cfg.Operator.PublicOrigin, SecureCookies: cfg.Operator.CookieMode == config.CookieModeSecure, Now: time.Now, Logger: logger})
	if err != nil {
		return components{}, err
	}
	mux := http.NewServeMux()
	mux.Handle("/api/v2/r/", scoped)
	mux.Handle("/api/v2/orgs/{orgID}/analytics/summary", scoped)
	mux.Handle("/api/v2/feedback/anonymous", scoped)
	mux.Handle("/api/operator/", api)
	mux.Handle("/api/v2/", api)
	refuseUnscoped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outcome := "not_committed"
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			outcome = "unavailable"
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(struct {
			Code      string `json:"code"`
			Outcome   string `json:"outcome"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		}{Code: "InvalidArgument", Outcome: outcome, Message: "select an explicit restaurant route"}); err != nil {
			logger.Printf("unscoped refusal response failed")
		}
	})
	mux.Handle("/api/serving/", refuseUnscoped)
	mux.Handle("/api/warehouse/", refuseUnscoped)
	mux.Handle("/api/live", refuseUnscoped)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"status":"ok","service":"umir-gateway"}`)); err != nil {
			logger.Printf("health response failed")
		}
	})
	expiry, err := expiration.NewScoped(expiration.ScopedOptions{GatewayEpoch: epoch, Auth: schedulerAuth{Client: client, registry: refresher}, Warehouse: business, Changes: changes, Interval: cfg.ExpirationRunInterval, Timeout: cfg.UpstreamTimeout, Concurrency: cfg.ExpirationConcurrency, IterationBudget: cfg.ExpirationIterationBudget, Now: env.now, NewRunID: newGatewayEpoch, NewTicker: env.newTicker, Logger: logger})
	if err != nil {
		return components{}, err
	}
	instance := cfg.InstanceID
	if instance == "" {
		if instance, err = newGatewayEpoch(); err != nil {
			return components{}, err
		}
	}
	mux.Handle("/readyz", httpapi.NewReadyz(instance, schedulerCapability(expiry, env.now), func() { logger.Printf("readiness response failed") }))
	runtime, err := httpapi.NewGatewayRuntime(httpapi.RuntimeOptions{Auth: client, ServiceKey: cfg.AuthRuntimeServiceKey, Epoch: epoch, TZDataVersion: "go1.26.9", Changes: changes})
	if err != nil {
		return components{}, err
	}
	return components{handler: httpapi.WithRequestID(mux, rand.Text), privateHandler: withDeadline(runtime, 5*time.Second), scopedStreams: streams, expiry: expiry, refresher: refresher}, nil
}

func newGatewayEpoch() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// schedulerAuth gives the scheduler Auth service tokens from the client and the registry from the
// refresher, so the scheduler never reads the registry itself.
type schedulerAuth struct {
	*authclient.Client
	registry *authclient.RegistryRefresher
}

func (a schedulerAuth) Registry(ctx context.Context) (expiration.Registry, error) {
	return a.registry.Registry(ctx)
}

// schedulerCapability reads the scheduler state for readiness. The scheduler logs its own changes.
func schedulerCapability(runner *expiration.ScopedRunner, now func() time.Time) func() string {
	return func() string { return runner.Health().State(now(), runner.Interval()) }
}
