package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/JustIkra/umir-gateway/internal/adapters/authclient"
	"github.com/JustIkra/umir-gateway/internal/adapters/httpupstream"
	"github.com/JustIkra/umir-gateway/internal/adapters/livecursor"
	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/journal"
	"github.com/JustIkra/umir-gateway/internal/live"
	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
	"github.com/JustIkra/umir-gateway/tests/fixtures/catalog"
	"github.com/JustIkra/umir-gateway/tests/fixtures/protocol"
)

type components struct {
	public, private http.Handler
	streams         *live.Handler
	runner          *expiration.ScopedRunner
	transport       *http.Transport
}

func assemble(cfg protocol.Config, keys map[string]string, clock *protocol.Clock, ticks *protocol.Ticks, epoch string, tzVersion string) (components, error) {
	logger := log.New(io.Discard, "", 0)
	transport := &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	authURL, err := url.Parse(cfg.ServiceURLs["auth"])
	if err != nil {
		return components{}, err
	}
	client, err := authclient.New(authclient.Options{URL: authURL, ServiceKey: keys["gateway-auth"], Timeout: 5 * time.Second, Transport: transport, Now: clock.Now})
	if err != nil {
		return components{}, err
	}
	api, err := operatorhttp.NewRemote(operatorhttp.RemoteOptions{Auth: client, Mode: operatorhttp.ModeLoopback, PublicOrigin: cfg.Origin, Logger: logger, Now: clock.Now, NewCommandID: func() string {
		id, e := protocol.UUID()
		if e != nil {
			return ""
		}
		return id
	}})
	if err != nil {
		return components{}, err
	}
	targets := map[string]httpupstream.ScopedTarget{}
	for _, name := range []string{"warehouse", "serving", "feedback"} {
		u, e := url.Parse(cfg.ServiceURLs[name])
		if e != nil {
			return components{}, e
		}
		targets[name] = httpupstream.ScopedTarget{URL: u, ServiceKey: keys["gateway-"+name]}
	}
	business, err := httpupstream.NewScopedClient(targets, transport, 5*time.Second)
	if err != nil {
		return components{}, err
	}
	codec, err := livecursor.New(keys["gateway-auth"])
	if err != nil {
		return components{}, err
	}
	changes, err := journal.NewScoped(epoch, 256, 10000, 4096, clock.Now, func() string {
		id, e := protocol.UUID()
		if e != nil {
			return ""
		}
		return id
	}, codec)
	if err != nil {
		return components{}, err
	}
	streams, err := live.NewHandler(live.ScopedOptions{Auth: client, Journal: changes, Clock: clock, PerSession: live.DefaultPerSession, Total: live.DefaultTotal, WriteTimeout: live.DefaultWriteTimeout, Logger: logger})
	if err != nil {
		return components{}, err
	}
	scoped, err := httpapi.NewScoped(httpapi.ScopedOptions{Live: streams, Changes: changes, Auth: client, Business: business, Origin: cfg.Origin, Now: clock.Now, Logger: logger})
	if err != nil {
		streams.Close()
		return components{}, err
	}
	mux := http.NewServeMux()
	for _, path := range []string{"/api/v2/r/", "/api/v2/orgs/", "/api/v2/feedback/anonymous"} {
		mux.Handle(path, scoped)
	}
	mux.Handle("/api/operator/", api)
	for _, path := range []string{"/csrf", "/session", "/me", "/me/display-name", "/me/password"} {
		mux.Handle("/api/v2"+path, api)
	}
	runtime, err := httpapi.NewGatewayRuntime(httpapi.RuntimeOptions{Auth: client, ServiceKey: keys["auth-gateway"], Epoch: epoch, TZDataVersion: tzVersion, Changes: changes})
	if err != nil {
		streams.Close()
		return components{}, err
	}
	runner, err := expiration.NewScoped(expiration.ScopedOptions{GatewayEpoch: epoch, Auth: client, Warehouse: business, Changes: changes, Interval: time.Minute, Timeout: 5 * time.Second, Now: clock.Now, NewRunID: protocol.UUID, NewTicker: ticks.NewTicker, IterationCompleted: ticks.Events, Logger: logger})
	if err != nil {
		streams.Close()
		return components{}, err
	}
	return components{public: httpapi.WithRequestID(mux, func() string {
		id, e := protocol.UUID()
		if e != nil {
			return ""
		}
		return id
	}), private: runtime, streams: streams, runner: runner, transport: transport}, nil
}
func unixListener(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	stat, err := os.Lstat(dir)
	if err != nil || !stat.IsDir() || stat.Mode().Perm() != 0700 {
		return nil, errors.New("unsafe control directory")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("control socket already exists")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	if err := protocol.CheckControlSocket(path); err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	return listener, nil
}
func serve(parent context.Context) error {
	cfg, configSHA, err := protocol.LoadConfig(protocol.ConfigPath)
	if err != nil {
		return errors.New("fixture configuration failed")
	}
	credential, err := protocol.ReadCredential(cfg.ControlCredentialFile)
	if err != nil {
		return errors.New("fixture credential failed")
	}
	keys := map[string]string{}
	for name, ref := range cfg.CredentialFiles {
		key, e := protocol.ReadCredential(ref)
		if e != nil {
			return errors.New("service credential failed")
		}
		keys[name] = key
	}
	instance, err := protocol.UUID()
	if err != nil {
		return err
	}
	epoch, err := protocol.UUID()
	if err != nil {
		return err
	}
	clock, err := protocol.NewClock(cfg.FixtureID, instance, cfg.InitialInstant, cfg.ClockGeneration)
	if err != nil {
		return err
	}
	ticks := protocol.NewTicks(clock)
	catalogReport, err := catalog.Observe(parent, catalogClock{clock})
	if err != nil {
		return errors.New("packaged catalog unavailable")
	}
	parts, err := assemble(cfg, keys, clock, ticks, epoch, catalogReport.Catalog.Version)
	if err != nil {
		return errors.New("fixture assembly failed")
	}
	defer parts.transport.CloseIdleConnections()
	defer parts.streams.Close()
	binarySHA, err := protocol.BinarySHA()
	if err != nil {
		return err
	}
	public, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.PublicPort))
	if err != nil {
		return err
	}
	private, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.PrivatePort))
	if err != nil {
		return errors.Join(err, public.Close())
	}
	control, err := unixListener(cfg.ControlSocket)
	if err != nil {
		return errors.Join(err, public.Close(), private.Close())
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	readyClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer readyClient.CloseIdleConnections()
	ready := func(ctx context.Context) bool {
		request, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:8082/internal/gateway/v2/runtime", nil)
		if e != nil {
			return false
		}
		request.Header.Set("X-Umir-Service-Key", keys["auth-gateway"])
		reply, e := readyClient.Do(request)
		if e != nil {
			return false
		}
		data, readErr := io.ReadAll(io.LimitReader(reply.Body, 8193))
		closeErr := reply.Body.Close()
		if readErr != nil || closeErr != nil || reply.StatusCode != 200 || len(data) > 8192 {
			return false
		}
		return protocol.RuntimeReady(data, epoch)
	}
	handler, err := protocol.NewHandler(protocol.HandlerOptions{Project: cfg.Project, Credential: credential, Clock: clock, Ticks: ticks, BinarySHA256: binarySHA, ConfigSHA256: configSHA, Ready: ready})
	if err != nil {
		return errors.Join(err, public.Close(), private.Close(), control.Close())
	}
	catalogHandler, err := catalog.NewHandler(catalog.Options{Project: cfg.Project, Credential: credential, Clock: catalogClock{clock}, BinarySHA256: binarySHA, ConfigSHA256: configSHA, Ready: func(ctx context.Context) bool { return clock.Read().Healthy && ticks.Available() && ready(ctx) }, Observe: catalog.Observe})
	if err != nil {
		return errors.Join(err, public.Close(), private.Close(), control.Close())
	}
	controlHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == catalog.Path {
			catalogHandler.ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
	servers := []*http.Server{{Handler: parts.public, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}, {Handler: parts.private, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}, {Handler: controlHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}}
	failures := make(chan error, 3)
	var owned sync.WaitGroup
	for i, listener := range []net.Listener{public, private, control} {
		owned.Go(func() {
			e := servers[i].Serve(listener)
			if !errors.Is(e, http.ErrServerClosed) {
				failures <- errors.New("fixture listener failed")
			}
		})
	}
	runnerDone := make(chan struct{})
	go func() { defer close(runnerDone); parts.runner.Run(ctx) }()
	baselineCtx, baselineCancel := context.WithTimeout(ctx, 6*time.Second)
	baseline := ticks.Baseline(baselineCtx)
	baselineCancel()
	var cause error
	if !baseline {
		cause = errors.New("scheduler startup observation unavailable")
	} else {
		select {
		case <-ctx.Done():
		case cause = <-failures:
		case <-runnerDone:
			cause = errors.New("scheduler exited")
		}
	}
	cancel()
	parts.streams.Close()
	shutdown, bound := context.WithTimeout(context.Background(), 5*time.Second)
	defer bound()
	for _, server := range servers {
		if e := server.Shutdown(shutdown); e != nil {
			cause = errors.Join(cause, errors.New("fixture shutdown failed"), server.Close())
		}
	}
	owned.Wait()
	<-runnerDone
	return cause
}
func main() {
	if len(os.Args) != 2 {
		if _, err := fmt.Fprintln(os.Stderr, "fixture invocation failed"); err != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
	if os.Args[1] == "healthcheck" {
		if err := protocol.Healthcheck(); err != nil {
			os.Exit(1)
		}
		return
	}
	if os.Args[1] != "serve" {
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, "fixture runtime failed"); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

type catalogClock struct{ *protocol.Clock }

func (c catalogClock) CatalogClock() catalog.ClockState {
	state := c.Read()
	return catalog.ClockState{Instant: moscowInstant(state.Instant), Generation: state.Generation, InstanceID: state.InstanceID, Source: "owner", Healthy: state.Healthy}
}

func moscowInstant(input string) string {
	instant, err := time.Parse(time.RFC3339Nano, input)
	if err != nil {
		return ""
	}
	return instant.In(time.FixedZone("Europe/Moscow", 3*60*60)).Format(time.RFC3339Nano)
}
