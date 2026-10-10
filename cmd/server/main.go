package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/JustIkra/umir-gateway/internal/adapters/httpupstream"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

// newHandler assembles the gateway: one proxy per upstream behind the router.
func newHandler(cfg config.Config) (http.Handler, error) {
	// Zero Proxy field: internal upstreams never go through HTTP_PROXY from the environment.
	transport := &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second}
	upstream := func(target *url.URL) (http.Handler, error) {
		proxy, err := httpupstream.NewProxy(target, transport)
		if err != nil {
			return nil, err
		}
		proxy.ErrorHandler = httpapi.WriteTransportError
		return withDeadline(proxy, cfg.UpstreamTimeout), nil
	}
	serving, err := upstream(cfg.ServingURL)
	if err != nil {
		return nil, fmt.Errorf("serving: %w", err)
	}
	warehouse, err := upstream(cfg.WarehouseURL)
	if err != nil {
		return nil, fmt.Errorf("warehouse: %w", err)
	}
	return httpapi.NewRouter(httpapi.Upstreams{Serving: serving, Warehouse: warehouse})
}

// withDeadline bounds the whole upstream exchange, including reading the client body;
// client cancellation still propagates.
func withDeadline(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline := time.Now().Add(timeout)
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		// The context cannot interrupt a blocked read of the client body, a read deadline can.
		// The server clears it once the body is consumed. Requests without a body are skipped:
		// the server already reads their connection in the background, and a read error there
		// cancels the context of every later request on the connection.
		if r.Body != http.NoBody {
			if err := http.NewResponseController(w).SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
				httpapi.WriteTransportError(w, r, err)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(cfg.Port); err != nil {
			log.Fatal(err)
		}
		return
	}
	app, err := newHandler(cfg)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-signals.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Printf("umir-gateway listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
