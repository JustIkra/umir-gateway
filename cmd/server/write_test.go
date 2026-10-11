package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/config"
)

type filler struct{}

func (filler) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func testConfig(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// serveGateway runs handler behind newServer, as main does, and returns its address.
func serveGateway(t *testing.T, cfg config.Config, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newServer(cfg, handler)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close gateway: %v", err)
		}
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve gateway: %v", err)
		}
	})
	return listener.Addr().String()
}

// largeUpstream streams size bytes and reports its start and request cancellation.
func largeUpstream(t *testing.T, size int64) (url string, started, cancelled <-chan struct{}) {
	t.Helper()
	begun, done := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(begun)
		go func() {
			<-r.Context().Done()
			close(done)
		}()
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		// The copy stops early when the gateway drops the upstream connection.
		if _, err := io.CopyN(w, filler{}, size); err != nil {
			t.Logf("upstream stream stopped: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)
	return upstream.URL, begun, done
}

func TestStalledReaderReleasesHandlerAtWriteTimeout(t *testing.T) {
	// Far larger than the socket buffers, so writes block once the client stops reading.
	upstreamURL, started, cancelled := largeUpstream(t, 256<<20)
	cfg := testConfig(t, map[string]string{
		"SERVING_URL": upstreamURL, "WAREHOUSE_URL": unusedUpstream(t),
		"UPSTREAM_TIMEOUT": "100ms", "WRITE_TIMEOUT": "800ms",
	})
	app, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	address := serveGateway(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		app.ServeHTTP(w, r)
	}))

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	// The caller keeps the socket open and never reads; it is closed only after the checks.
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close caller: %v", err)
		}
	})
	if _, err := fmt.Fprint(conn, "GET /api/serving/large HTTP/1.1\r\nHost: gateway\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not start in 2 seconds")
	}
	select {
	case <-cancelled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("upstream was not cancelled by the 100ms UPSTREAM_TIMEOUT before the write deadline")
	}
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("handler still blocked 2 seconds after the request while the caller did not read")
	}
}

func TestReadingClientReceivesLargeResponse(t *testing.T) {
	const size = 16 << 20
	upstreamURL, _, _ := largeUpstream(t, size)
	cfg := testConfig(t, map[string]string{
		"SERVING_URL": upstreamURL, "WAREHOUSE_URL": unusedUpstream(t),
		"UPSTREAM_TIMEOUT": "5s", "WRITE_TIMEOUT": "6s",
	})
	app, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	address := serveGateway(t, cfg, app)

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get("http://" + address + "/api/serving/large")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Errorf("close response: %v", closeErr)
	}
	if err != nil || response.StatusCode != http.StatusOK || len(body) != size {
		t.Fatalf("response: %d, %d bytes, %v", response.StatusCode, len(body), err)
	}
	if !bytes.Equal(body, bytes.Repeat([]byte{'x'}, size)) {
		t.Fatal("response body differs from the upstream body")
	}
}

func TestGatewayTimeoutIsDeliveredBeforeWriteTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http notices the dropped connection only after the body is consumed.
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		<-r.Context().Done()
	}))
	defer upstream.Close()
	// WRITE_TIMEOUT is derived from UPSTREAM_TIMEOUT, leaving time for the gateway's own error.
	cfg := testConfig(t, map[string]string{
		"SERVING_URL": upstream.URL, "WAREHOUSE_URL": unusedUpstream(t), "UPSTREAM_TIMEOUT": "100ms",
	})
	app, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	address := serveGateway(t, cfg, app)

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Post("http://"+address+"/api/serving/order-confirmations", "application/json",
		bytes.NewReader([]byte(`{"commandID":"c-1","proposalID":"p-1"}`)))
	if err != nil {
		t.Fatalf("gateway timeout response was lost: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Errorf("close response: %v", closeErr)
	}
	if err != nil || response.StatusCode != http.StatusGatewayTimeout || !bytes.Contains(body, []byte(`"outcome":"unknown"`)) {
		t.Fatalf("response: %d %s %v", response.StatusCode, body, err)
	}
}
