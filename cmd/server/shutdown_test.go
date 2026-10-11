package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

const processEnv = "UMIR_GATEWAY_TEST_PROCESS"

// TestMain lets a test start this binary as the real gateway process.
func TestMain(m *testing.M) {
	if os.Getenv(processEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

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

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitHealthy(t *testing.T, base string, exited <-chan struct{}) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatal("gateway exited during start")
		default:
		}
		if response, err := client.Get(base + "/healthz"); err == nil {
			healthy := response.StatusCode == http.StatusOK
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if healthy {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gateway did not become healthy in 5 seconds")
}

func TestSIGTERMWaitsForActiveResponse(t *testing.T) {
	upstreamURL, received, release := heldUpstream(t)
	port := freePort(t)
	var logs bytes.Buffer
	process := exec.Command(os.Args[0])
	process.Env = append(os.Environ(), processEnv+"=1", "PORT="+port,
		"SERVING_URL="+upstreamURL, "WAREHOUSE_URL="+upstreamURL, "UPSTREAM_TIMEOUT=30s")
	process.Stderr = &logs
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	// exitErr is read only after exited is closed.
	var exitErr error
	exited := make(chan struct{})
	go func() {
		exitErr = process.Wait()
		close(exited)
	}()
	defer func() {
		select {
		case <-exited:
		default:
			if err := process.Process.Kill(); err != nil {
				t.Errorf("kill gateway: %v", err)
			}
			<-exited
		}
	}()

	base := "http://127.0.0.1:" + port
	waitHealthy(t, base, exited)
	responses := requestHeld(base + "/api/serving/held")
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive the request in 5 seconds")
	}
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case <-exited:
		// Wait has returned, so the stderr copy is complete.
		t.Fatalf("gateway exited before the held response was delivered: %v\n%s", exitErr, logs.String())
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case response := <-responses:
		if response.err != nil || response.status != http.StatusOK || response.body != "upstream response" {
			t.Fatalf("response: %d %q %v", response.status, response.body, response.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("held response was not delivered in 5 seconds")
	}
	select {
	case <-exited:
		if exitErr != nil {
			t.Fatalf("gateway exit: %v\n%s", exitErr, logs.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not exit in 5 seconds after draining")
	}
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
