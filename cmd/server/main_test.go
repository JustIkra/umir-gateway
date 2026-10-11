package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/config"
)

func gateway(t *testing.T, servingURL, warehouseURL string, timeout string) http.Handler {
	t.Helper()
	cfg, err := config.Load(func(key string) string {
		return map[string]string{"SERVING_URL": servingURL, "WAREHOUSE_URL": warehouseURL, "UPSTREAM_TIMEOUT": timeout}[key]
	})
	if err != nil {
		t.Fatal(err)
	}
	app, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func transportError(t *testing.T, response *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d %q is not a transport error", response.Code, response.Body)
	}
	return body
}

func unusedUpstream(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream request: %s", r.URL)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestProxyRoutesPreserveRequestAndResponse(t *testing.T) {
	for _, service := range []string{"serving", "warehouse"} {
		t.Run(service, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/orders" || r.URL.RawQuery != "limit=2" || r.Method != http.MethodPost {
					t.Errorf("request: %s %s", r.Method, r.URL)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
					return
				}
				if string(body) != "payload" {
					t.Errorf("body: %s", body)
				}
				w.Header().Set("X-Upstream", service)
				w.WriteHeader(http.StatusAccepted)
				if _, err := w.Write([]byte("accepted")); err != nil {
					t.Errorf("write upstream response: %v", err)
				}
			}))
			defer upstream.Close()
			urls := map[string]string{"serving": unusedUpstream(t), "warehouse": unusedUpstream(t)}
			urls[service] = upstream.URL
			app := gateway(t, urls["serving"], urls["warehouse"], "")

			response := httptest.NewRecorder()
			app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/"+service+"/orders?limit=2", strings.NewReader("payload")))
			if response.Code != http.StatusAccepted || response.Header().Get("X-Upstream") != service || response.Body.String() != "accepted" {
				t.Fatalf("response: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestLostResponseAfterWriteIsUnknownAndNotRetried(t *testing.T) {
	var received atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read upstream body: %v", err)
			return
		}
		received.Add(1)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		if err := conn.Close(); err != nil {
			t.Errorf("close upstream connection: %v", err)
		}
	}))
	defer upstream.Close()
	app := gateway(t, upstream.URL, unusedUpstream(t), "")

	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/serving/order-confirmations",
		strings.NewReader(`{"commandID":"c-1","proposalID":"p-1"}`)))

	body := transportError(t, response)
	if response.Code != http.StatusBadGateway || body["code"] != "UpstreamUnavailable" || body["outcome"] != "unknown" {
		t.Fatalf("response: %d %v", response.Code, body)
	}
	if got := received.Load(); got != 1 {
		t.Fatalf("upstream received the write %d times", got)
	}
}

func TestUnreachableUpstreamReadIsUnavailable(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	app := gateway(t, unusedUpstream(t), closed.URL, "")

	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/warehouse/inventory", nil))

	body := transportError(t, response)
	if response.Code != http.StatusBadGateway || body["outcome"] != "unavailable" {
		t.Fatalf("response: %d %v", response.Code, body)
	}
}

func TestSlowUpstreamTimesOutAndIsCancelled(t *testing.T) {
	cancelled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()
	app := gateway(t, upstream.URL, unusedUpstream(t), "100ms")

	started := time.Now()
	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/serving/menu", nil))

	body := transportError(t, response)
	if response.Code != http.StatusGatewayTimeout || body["code"] != "UpstreamTimeout" || body["outcome"] != "unavailable" {
		t.Fatalf("response: %d %v", response.Code, body)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request was not cancelled")
	}
}

func TestStalledRequestBodyIsBoundedByUpstreamTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("read stalled upstream body: %v", err)
		}
	}))
	defer upstream.Close()
	front := httptest.NewServer(gateway(t, upstream.URL, unusedUpstream(t), "100ms"))
	defer front.Close()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close client connection: %v", err)
		}
	}()
	// Far beyond the budget: an unbounded body read fails here instead of hanging the test.
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Content-Length promises two bytes; the client sends one and stalls.
	request := "POST /api/serving/order-confirmations HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("no response within the budget: %v", err)
	}
	var body map[string]string
	err = json.NewDecoder(response.Body).Decode(&body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Errorf("close timeout response: %v", closeErr)
	}
	if err != nil || response.StatusCode != http.StatusGatewayTimeout || body["code"] != "UpstreamTimeout" || body["outcome"] != "unknown" {
		t.Fatalf("response: %d %v %v", response.StatusCode, body, err)
	}
	// The unread rest of the body must not be parsed as the next request on this connection.
	if rest, err := io.ReadAll(reader); len(rest) != 0 || err != nil {
		t.Fatalf("connection was not closed: %q %v", rest, err)
	}
}

func TestTimeoutKeepsClientConnectionUsable(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.ReadAll(r.Body); err != nil {
					t.Errorf("read upstream body: %v", err)
					return
				}
				if calls.Add(1) == 1 {
					<-r.Context().Done()
					return
				}
				if _, err := io.WriteString(w, "ok"); err != nil {
					t.Errorf("write upstream response: %v", err)
				}
			}))
			defer upstream.Close()
			front := httptest.NewServer(gateway(t, upstream.URL, unusedUpstream(t), "100ms"))
			defer front.Close()

			// The second request reuses the keep-alive connection of the timed out one.
			for i, want := range []int{http.StatusGatewayTimeout, http.StatusOK} {
				var body io.Reader
				if method == http.MethodPost {
					body = strings.NewReader(`{}`)
				}
				request, err := http.NewRequest(method, front.URL+"/api/serving/menu", body)
				if err != nil {
					t.Fatal(err)
				}
				response, err := front.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Errorf("read response body: %v", err)
				}
				if err := response.Body.Close(); err != nil {
					t.Errorf("close response body: %v", err)
				}
				if response.StatusCode != want {
					t.Fatalf("request %d: %d, want %d", i+1, response.StatusCode, want)
				}
			}
		})
	}
}

func TestClientCancellationReachesUpstream(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http watches for a closed connection only after the body is consumed.
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read upstream body: %v", err)
			return
		}
		close(started)
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()
	front := httptest.NewServer(gateway(t, upstream.URL, unusedUpstream(t), ""))
	defer front.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, front.URL+"/api/serving/order-proposals", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-started
		cancel()
	}()
	if response, err := front.Client().Do(request); err == nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Errorf("close response body: %v", closeErr)
		}
		t.Fatalf("request completed: %d", response.StatusCode)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("client cancellation did not reach upstream")
	}
}

func TestMalformedQueryReachesServiceValidation(t *testing.T) {
	for _, query := range []string{"unexpected=%ZZ", "dishID=d1&unexpected=%ZZ", "dishID=d1;unexpected=x"} {
		t.Run(query, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RawQuery != query {
					t.Errorf("query changed before validation: got %q, want %q", r.URL.RawQuery, query)
				}
				if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			app := gateway(t, upstream.URL, upstream.URL, "")
			response := httptest.NewRecorder()
			app.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/serving/dish?"+query, nil))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid query was accepted after proxying: status %d", response.Code)
			}
		})
	}
}

type failingDeadlineRecorder struct {
	*httptest.ResponseRecorder
	err error
}

func (writer failingDeadlineRecorder) SetReadDeadline(time.Time) error {
	return writer.err
}

func TestReadDeadlineFailureDoesNotCallUpstream(t *testing.T) {
	var calls int
	app := withDeadline(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}), time.Second)
	response := failingDeadlineRecorder{httptest.NewRecorder(), errors.New("fixture read deadline failure")}
	app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/serving/order-confirmations", strings.NewReader(`{}`)))
	body := transportError(t, response.ResponseRecorder)
	if calls != 0 || response.Code != http.StatusBadGateway || body["outcome"] != "unknown" {
		t.Fatalf("calls=%d, response=%d %v", calls, response.Code, body)
	}
}
