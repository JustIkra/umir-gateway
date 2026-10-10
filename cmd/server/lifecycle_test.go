package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

type streamReader struct{}

func (streamReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}

func TestStalledDownstreamWriteEndsWithinBudget(t *testing.T) {
	testStalledWrite(t, "100ms", 0)
}

func TestStalledWriteUsesEarlierIncomingDeadline(t *testing.T) {
	testStalledWrite(t, "5s", 100*time.Millisecond)
}

func testStalledWrite(t *testing.T, timeout string, parentTimeout time.Duration) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(256<<20, 10))
		if _, err := io.CopyN(w, streamReader{}, 256<<20); err != nil {
			return
		}
	}))
	defer upstream.Close()
	done := make(chan struct{})
	app := gateway(t, upstream.URL, upstream.URL, timeout)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		if parentTimeout > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), parentTimeout)
			defer cancel()
			r = r.WithContext(ctx)
		}
		app.ServeHTTP(w, r)
	}))
	defer front.Close()
	conn, err := net.DialTimeout("tcp", front.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("close client: %v", closeErr)
		}
	}()
	if _, err := io.WriteString(conn, "GET /api/serving/large HTTP/1.1\r\nHost: gateway\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway stayed blocked writing to a client that stopped reading")
	}
}

func TestGatewayChildProcess(t *testing.T) {
	if os.Getenv("UMIR_GATEWAY_TEST_CHILD") != "1" {
		return
	}
	main()
}

func TestSIGTERMDrainsActiveResponseBeforeProcessExit(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
			if _, err := io.WriteString(w, "completed"); err != nil {
				t.Errorf("write upstream: %v", err)
			}
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
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
	child := exec.Command(os.Args[0], "-test.run=^TestGatewayChildProcess$")
	child.Env = append(os.Environ(), "UMIR_GATEWAY_TEST_CHILD=1", "PORT="+port,
		"SERVING_URL="+upstream.URL, "WAREHOUSE_URL="+upstream.URL, "UPSTREAM_TIMEOUT=5s")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	processDone := make(chan struct{})
	go func() {
		exited <- child.Wait()
		close(processDone)
	}()
	defer func() {
		select {
		case <-processDone:
		default:
			if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("stop child: %v", err)
			}
			select {
			case <-processDone:
			case <-time.After(2 * time.Second):
				t.Error("child did not stop")
			}
		}
	}()
	address := "http://127.0.0.1:" + port
	waitChildHealthy(t, address, exited)
	client := &http.Client{Timeout: 5 * time.Second}
	responseDone := make(chan error, 1)
	go func() {
		response, err := client.Get(address + "/api/serving/menu")
		if err != nil {
			responseDone <- err
			return
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || string(body) != "completed" {
			readErr = errors.Join(readErr, fmt.Errorf("response: %d %q", response.StatusCode, body))
		}
		responseDone <- errors.Join(readErr, closeErr)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("active request did not reach upstream")
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		close(release)
		t.Fatalf("gateway exited before draining its active request: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-responseDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active response was not drained")
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not exit after draining")
	}
}

func waitChildHealthy(t *testing.T, address string, exited <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	for {
		response, err := client.Get(address + "/healthz")
		if err == nil {
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if response.StatusCode == http.StatusOK && readErr == nil && closeErr == nil {
				return
			}
		}
		select {
		case <-ticker.C:
		case err := <-exited:
			t.Fatalf("child startup: %v", err)
		case <-ctx.Done():
			t.Fatal("child health deadline")
		}
	}
}

func TestBudgetDoesNotDiscardTransportTimeoutResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer upstream.Close()
	front := httptest.NewServer(gateway(t, upstream.URL, upstream.URL, "100ms"))
	defer front.Close()
	connection, err := net.DialTimeout("tcp", front.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	}()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "GET /api/serving/menu HTTP/1.1\r\nHost: gateway\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusGatewayTimeout || readErr != nil || closeErr != nil {
		t.Fatalf("timeout response: %d %v %v", response.StatusCode, readErr, closeErr)
	}
}
