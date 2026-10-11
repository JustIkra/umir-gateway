package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type heldResponse struct {
	status int
	body   string
	err    error
}

// heldUpstream answers only after release; received closes when the request arrives.
func heldUpstream(t *testing.T) (url string, received <-chan struct{}, release func()) {
	t.Helper()
	arrived, released := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(released) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-released
		if _, err := io.WriteString(w, "upstream response"); err != nil {
			t.Logf("write held response: %v", err)
		}
	}))
	// Cleanups run in reverse order: the handler is released before the server waits for it.
	t.Cleanup(upstream.Close)
	t.Cleanup(release)
	return upstream.URL, arrived, release
}

func requestHeld(url string) <-chan heldResponse {
	responses := make(chan heldResponse, 1)
	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		response, err := client.Get(url)
		if err != nil {
			responses <- heldResponse{err: err}
			return
		}
		body, err := io.ReadAll(response.Body)
		responses <- heldResponse{status: response.StatusCode, body: string(body), err: errors.Join(err, response.Body.Close())}
	}()
	return responses
}

func TestRunReturnsServeFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
	stopped := make(chan error, 1)
	go func() { stopped <- run(context.Background(), server, listener, time.Second) }()

	select {
	case err := <-stopped:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("serve failure was lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run kept waiting for a stop signal after serving failed")
	}
}

func TestShutdownClosesConnectionsAfterGracePeriod(t *testing.T) {
	upstreamURL, received, _ := heldUpstream(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: gateway(t, upstreamURL, unusedUpstream(t), "30s"), ReadHeaderTimeout: time.Second}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopped := make(chan error, 1)
	go func() { stopped <- run(ctx, server, listener, 100*time.Millisecond) }()

	responses := requestHeld("http://" + listener.Addr().String() + "/api/serving/held")
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive the request in 5 seconds")
	}
	stop()

	select {
	case err := <-stopped:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("run result after grace period: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return within 2 seconds after the grace period")
	}
	// The upstream still holds the response: only the forced close can end this request.
	select {
	case response := <-responses:
		if response.err == nil {
			t.Fatalf("held request completed: %d %q", response.status, response.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forced close did not reach the client within 2 seconds")
	}
}
