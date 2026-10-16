package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/JustIkra/umir-gateway/internal/adapters/accountfile"
	"github.com/JustIkra/umir-gateway/internal/adapters/argon2id"
	"github.com/JustIkra/umir-gateway/internal/adapters/httpupstream"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/journal"
	"github.com/JustIkra/umir-gateway/internal/live"
	"github.com/JustIkra/umir-gateway/internal/operator"
	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

// newToken returns 128 bits of randomness as cookie-safe text.
func newToken() (string, error) { return rand.Text(), nil }

// newAccounts opens the account file, creating it from the bootstrap settings only when it is absent,
// and starts the operator account module; observer, when set, hears about extended and ended sessions.
func newAccounts(cfg config.Operator, observer operator.SessionObserver) (*operator.Service, error) {
	hasher, err := argon2id.New(argon2id.Selected, rand.Reader)
	if err != nil {
		return nil, err
	}
	state, store, err := accountfile.Open(cfg.StorePath, accountfile.Bootstrap{
		Login: cfg.BootstrapLogin, DisplayName: cfg.BootstrapDisplayName, PasswordHash: cfg.BootstrapPasswordHash,
	}, accountfile.Options{
		NewProfileID: newToken,
		Validate: func(state operator.State) error {
			if err := operator.ValidateState(state); err != nil {
				return err
			}
			return hasher.Check(state.Account.PasswordHash)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("operator account: %w", err)
	}
	return operator.NewService(state, operator.Options{
		Store: store, Hasher: hasher, Now: time.Now, NewToken: newToken,
		IdleTimeout: cfg.IdleTimeout, AbsoluteTimeout: cfg.AbsoluteTimeout, RememberTimeout: operator.DefaultRememberTimeout,
		MaxSessions: operator.DefaultMaxSessions, MaxAnonymous: operator.DefaultMaxAnonymous,
		AnonymousTTL: operator.DefaultAnonymousTTL, MaxVerifications: operator.DefaultMaxVerifications,
		MaxQueuedLogins: operator.DefaultMaxQueuedLogins, FailureLimit: operator.DefaultFailureLimit,
		FailureWindow: operator.DefaultFailureWindow, Cooldown: operator.DefaultCooldown,
		FeedbackContextLimit: operator.DefaultFeedbackContextLimit, FeedbackProcessLimit: operator.DefaultFeedbackProcessLimit,
		FeedbackWindow: operator.DefaultFeedbackWindow, Observer: observer,
	})
}

// components are the parts of one gateway process: the HTTP handler, the change journal, the live
// streams and the expiration runs.
type components struct {
	handler        http.Handler
	privateHandler http.Handler
	journal        *journal.Journal
	scopedStreams  *live.Handler
	streams        *live.Streams
	expiry         interface{ Run(context.Context) }
	refresher      interface{ Run(context.Context) }
}

// newComponents assembles the gateway from cfg. Nothing runs yet: the process serves handler and
// starts expiry itself.
func newComponents(cfg config.Config, logger *log.Logger) (components, error) {
	if cfg.AuthURL != nil {
		return newAuthComponents(cfg, logger)
	}
	events := live.NewSessionEvents()
	accounts, err := newAccounts(cfg.Operator, events)
	if err != nil {
		return components{}, err
	}
	changes, err := journal.New(cfg.JournalCapacity, rand.Text, time.Now)
	if err != nil {
		return components{}, err
	}
	upstream := live.NewUpstream()
	streams, err := live.NewStreams(live.Options{
		Changes: changes, Upstream: upstream, Sessions: accounts, Events: events, Clock: live.SystemClock{},
		PerSession: live.DefaultPerSession, Total: live.DefaultTotal, Ping: live.DefaultPing, WriteTimeout: live.DefaultWriteTimeout,
	})
	if err != nil {
		return components{}, err
	}
	// Zero Proxy field: internal upstreams never go through HTTP_PROXY from the environment.
	transport := &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second}
	handler, err := newHandler(cfg, accounts, transport, changes, streams, logger)
	if err != nil {
		return components{}, err
	}
	expiry, err := expiration.New(expiration.Options{
		Client: &http.Client{Transport: transport}, Warehouse: cfg.WarehouseURL, Interval: cfg.ExpirationRunInterval,
		Timeout: cfg.UpstreamTimeout, Journal: changes, Upstream: upstream, NewTicker: newTicker, Logger: logger,
	})
	if err != nil {
		return components{}, err
	}
	return components{handler: handler, journal: changes, streams: streams, expiry: expiry}, nil
}

func newTicker(d time.Duration) (<-chan time.Time, func()) {
	ticker := time.NewTicker(d)
	return ticker.C, ticker.Stop
}

// newHandler assembles the gateway: one proxy per upstream behind the operator guard and the router.
// Each upstream is wrapped so operator credentials never reach it and it cannot set them. Admitted
// writes go to changes; GET /api/live is served by streams.
func newHandler(cfg config.Config, accounts operatorhttp.Accounts, transport http.RoundTripper, changes *journal.Journal,
	streams *live.Streams, logger *log.Logger) (http.Handler, error) {
	proxy := func(target *url.URL) (http.Handler, error) {
		proxy, err := httpupstream.NewProxy(target, transport)
		if err != nil {
			return nil, err
		}
		proxy.ErrorHandler = httpapi.WriteTransportError
		proxy.ModifyResponse = operatorhttp.DropReservedCookies
		return operatorhttp.StripCredentials(proxy), nil
	}
	upstream := func(target *url.URL) (http.Handler, error) {
		h, err := proxy(target)
		if err != nil {
			return nil, err
		}
		return withDeadline(h, cfg.UpstreamTimeout), nil
	}
	serving, err := upstream(cfg.ServingURL)
	if err != nil {
		return nil, fmt.Errorf("serving: %w", err)
	}
	warehouse, err := upstream(cfg.WarehouseURL)
	if err != nil {
		return nil, fmt.Errorf("warehouse: %w", err)
	}
	// The feedback guard reads the body itself, so the deadline wraps the guard: the body is read under
	// the exchange budget, and no read deadline is set once the connection is idle again.
	feedback, err := proxy(cfg.FeedbackURL)
	if err != nil {
		return nil, fmt.Errorf("feedback: %w", err)
	}
	api, err := operatorhttp.New(operatorhttp.Options{
		Accounts: accounts, Mode: operatorhttp.CookieMode(cfg.Operator.CookieMode),
		PublicOrigin: cfg.Operator.PublicOrigin, Logger: logger, Now: time.Now,
	})
	if err != nil {
		return nil, err
	}
	return httpapi.NewRouter(httpapi.Routes{
		Serving: serving, Warehouse: warehouse, Operator: api, Protect: api.Protect,
		Feedback: feedback, NewRequestID: rand.Text,
		GuardFeedback: func(next http.Handler) http.Handler {
			return withDeadline(api.GuardFeedback(next), cfg.UpstreamTimeout)
		},
		Record: func(method, path string, status int) {
			changes.Append(journal.Entry{Source: journal.SourceRequest, Method: method, Path: path, Status: status, Outcome: journal.OutcomeOf(status)})
		},
		// The stream is not bounded by the upstream deadline: it stays open until the client, the
		// session or the server ends it.
		Live: api.GuardLive(streams.Serve),
	})
}

// withDeadline bounds the whole upstream exchange, including reading the client body;
// client cancellation still propagates.
func withDeadline(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline := time.Now().Add(timeout)
		if parentDeadline, ok := r.Context().Deadline(); ok && parentDeadline.Before(deadline) {
			deadline = parentDeadline
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			httpapi.WriteTransportError(w, r, err)
			return
		}
		// The context cannot interrupt a blocked read of the client body, a read deadline can.
		// The server clears it once the body is consumed. Requests without a body are skipped:
		// the server already reads their connection in the background, and a read error there
		// cancels the context of every later request on the connection.
		if r.Body != http.NoBody {
			if err := controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
				httpapi.WriteTransportError(w, r, err)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const shutdownGrace = 10 * time.Second

// newServer serves app. Shutdown waits for idle connections, and a live stream never becomes idle, so
// shutdown also ends the streams.
func newServer(cfg config.Config, app components) *http.Server {
	server := &http.Server{
		Addr:              listenAddress(cfg),
		Handler:           app.handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if app.streams != nil {
		server.RegisterOnShutdown(app.streams.Close)
	}
	if app.scopedStreams != nil {
		server.RegisterOnShutdown(app.scopedStreams.Close)
	}
	return server
}

// listenAddress binds LISTEN_HOST: loopback for a process started by hand, all interfaces in the image.
func listenAddress(cfg config.Config) string { return net.JoinHostPort(cfg.ListenHost, cfg.Port) }

func run(ctx context.Context, server *http.Server, listener net.Listener, grace time.Duration) error {
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(fmt.Errorf("graceful shutdown: %w", shutdownErr), server.Close())
	}
	serveErr := <-served
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(shutdownErr, serveErr)
}

// healthPath is the path the image healthcheck probes: the Auth mode answers capability readiness,
// the legacy mode only liveness.
func healthPath(cfg config.Config) string {
	if cfg.AuthURL != nil {
		return "/readyz"
	}
	return "/healthz"
}

func healthcheck(port, path string) (result error) {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + port + path)
	if err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, response.Body.Close())
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health status: %d", response.StatusCode)
	}
	return nil
}

func main() {
	// hash-password runs before configuration: it is used to create the bootstrap settings.
	if len(os.Args) >= 2 && os.Args[1] == "hash-password" {
		os.Exit(runHashPassword(os.Args[2:]))
	}
	// serve is the explicit name of the default command; Gateway has no database, so no migrate or
	// generation commands exist.
	// An option-like first argument (the test runner's flags) names no command.
	if len(os.Args) >= 2 && !strings.HasPrefix(os.Args[1], "-") && (!slices.Contains([]string{"serve", "healthcheck", "clear-sessions"}, os.Args[1]) || len(os.Args) > 2) {
		log.Fatal("usage: server [serve|healthcheck|hash-password|clear-sessions]")
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 2 && os.Args[1] == "clear-sessions" {
		if cfg.AuthURL != nil {
			log.Fatal("clear-sessions is a legacy-only command; use Auth logout-all after cutover")
		}
		if err := clearSessions(cfg.Operator, os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(cfg.Port, healthPath(cfg)); err != nil {
			log.Fatal(err)
		}
		return
	}
	app, err := newComponents(cfg, log.Default())
	if err != nil {
		log.Fatal(err)
	}
	server := newServer(cfg, app)
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("umir-gateway listening on %s", server.Addr)
	// The process owns the background loops, the registry refresher and the expiration runs: they stop
	// with the signal and finish before it exits.
	runs := make(chan struct{})
	go func() {
		defer close(runs)
		var loops sync.WaitGroup
		for _, loop := range []interface{ Run(context.Context) }{app.refresher, app.expiry} {
			if loop != nil {
				loops.Go(func() { loop.Run(signals) })
			}
		}
		loops.Wait()
	}()
	if app.privateHandler != nil {
		privateServer := &http.Server{Addr: net.JoinHostPort(cfg.PrivateListenHost, cfg.PrivatePort), Handler: app.privateHandler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
		privateListener, listenErr := net.Listen("tcp", privateServer.Addr)
		if listenErr != nil {
			stop()
			<-runs
			if closeErr := listener.Close(); closeErr != nil {
				log.Printf("public listener close failed")
			}
			log.Fatal("private listener unavailable")
		}
		err = runPair(signals, server, listener, privateServer, privateListener)
	} else {
		err = run(signals, server, listener, shutdownGrace)
	}
	stop()
	<-runs
	if err != nil {
		log.Fatal(err)
	}
}

func runPair(parent context.Context, public *http.Server, publicListener net.Listener, private *http.Server, privateListener net.Listener) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- run(ctx, public, publicListener, shutdownGrace) }()
	go func() { results <- run(ctx, private, privateListener, shutdownGrace) }()
	first := <-results
	cancel()
	return errors.Join(first, <-results)
}
