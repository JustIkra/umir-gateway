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
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/JustIkra/umir-gateway/internal/adapters/accountfile"
	"github.com/JustIkra/umir-gateway/internal/adapters/argon2id"
	"github.com/JustIkra/umir-gateway/internal/adapters/httpupstream"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/operator"
	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

// newToken returns 128 bits of randomness as cookie-safe text.
func newToken() (string, error) { return rand.Text(), nil }

// newAccounts opens the account file, creating it from the bootstrap settings only when it is absent,
// and starts the operator account module.
func newAccounts(cfg config.Operator) (*operator.Service, error) {
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
		FeedbackWindow: operator.DefaultFeedbackWindow,
	})
}

// newHandler assembles the gateway: one proxy per upstream behind the operator guard and the router.
// Each upstream is wrapped so operator credentials never reach it and it cannot set them.
func newHandler(cfg config.Config, accounts operatorhttp.Accounts, logger *log.Logger) (http.Handler, error) {
	// Zero Proxy field: internal upstreams never go through HTTP_PROXY from the environment.
	transport := &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second}
	upstream := func(target *url.URL) (http.Handler, error) {
		proxy, err := httpupstream.NewProxy(target, transport)
		if err != nil {
			return nil, err
		}
		proxy.ErrorHandler = httpapi.WriteTransportError
		proxy.ModifyResponse = operatorhttp.DropReservedCookies
		return operatorhttp.StripCredentials(withDeadline(proxy, cfg.UpstreamTimeout)), nil
	}
	serving, err := upstream(cfg.ServingURL)
	if err != nil {
		return nil, fmt.Errorf("serving: %w", err)
	}
	warehouse, err := upstream(cfg.WarehouseURL)
	if err != nil {
		return nil, fmt.Errorf("warehouse: %w", err)
	}
	feedback, err := upstream(cfg.FeedbackURL)
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
		Feedback: feedback, GuardFeedback: api.GuardFeedback, NewRequestID: rand.Text,
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

func healthcheck(port string) (result error) {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + port + "/healthz")
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
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 2 && os.Args[1] == "clear-sessions" {
		if err := clearSessions(cfg.Operator, os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(cfg.Port); err != nil {
			log.Fatal(err)
		}
		return
	}
	accounts, err := newAccounts(cfg.Operator)
	if err != nil {
		log.Fatal(err)
	}
	app, err := newHandler(cfg, accounts, log.Default())
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              listenAddress(cfg),
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("umir-gateway listening on %s", server.Addr)
	if err := run(signals, server, listener, shutdownGrace); err != nil {
		log.Fatal(err)
	}
}
