package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a log sink the Gateway goroutines may write while the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const w1BrowserRequestID = "browser-chosen-id"

func TestW1RequestIDIsFreshReturnedAndForwarded(t *testing.T) {
	for name, fail := range map[string]bool{"success": false, "owner failure": true} {
		t.Run(name, func(t *testing.T) {
			f := newScopedFixture(t)
			f.peer = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if fail {
					writeScopedJSON(t, w, map[string]any{"unexpected": "shape"}) // fails response validation: 502
					return
				}
				page := summaryPage(scopedRestaurant, "stock", true)
				writeScopedJSON(t, w, map[string]any{"context": page["context"], "result": map[string]any{"items": page["items"]}})
			}
			w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", map[string]string{"X-Request-ID": w1BrowserRequestID})
			if fail && w.Code != http.StatusBadGateway {
				t.Fatalf("expected the owner failure to be 502, got %d %s", w.Code, w.Body)
			}
			id := w.Header().Get("X-Request-ID")
			if id == "" || id == w1BrowserRequestID {
				t.Fatalf("response request ID %q must be new", id)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != 1 || f.requests[0].Header.Get("X-Request-ID") != id {
				t.Fatalf("owner saw %v, want %q", f.requests, id)
			}
			if len(f.authRequestIDs) == 0 {
				t.Fatal("Auth was not called")
			}
			for _, seen := range f.authRequestIDs {
				if seen != id {
					t.Fatalf("Auth saw request ID %q, want %q", seen, id)
				}
			}
		})
	}
}

func TestW1RequestIDOnRefusalBeforeAnyUpstream(t *testing.T) {
	f := newScopedFixture(t)
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/unknown-route", "", map[string]string{"X-Request-ID": w1BrowserRequestID})
	if id := w.Header().Get("X-Request-ID"); id == "" || id == w1BrowserRequestID {
		t.Fatalf("refusal request ID %q", id)
	}
}

type w1LogRecord struct {
	Msg        string `json:"msg"`
	RequestID  string `json:"request_id"`
	Owner      string `json:"owner"`
	Operation  string `json:"operation"`
	Restaurant string `json:"restaurant_id"`
	Status     int    `json:"status"`
	Class      string `json:"class"`
	DurationMS *int64 `json:"duration_ms"`
}

func w1FailureRecords(t *testing.T, logs string) []w1LogRecord {
	t.Helper()
	var records []w1LogRecord
	for _, line := range strings.Split(logs, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var record w1LogRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if record.Msg == "upstream_failure" {
			records = append(records, record)
		}
	}
	return records
}

func TestW1UpstreamFailureLogHasReasonButNoSecrets(t *testing.T) {
	cases := map[string]struct {
		setup        func(f *scopedFixture)
		owner, class string
		status       int
	}{
		"owner schema drift": {func(f *scopedFixture) {
			f.peer = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				writeScopedJSON(t, w, map[string]any{"leaked": "owner-body-secret"})
			}
		}, "warehouse", "schema", http.StatusBadGateway},
		"auth invalid response": {func(f *scopedFixture) {
			f.authHook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/internal/auth/v1/authorize" {
					return false
				}
				w.Header().Set("Content-Type", "text/plain")
				if _, err := w.Write([]byte("auth-body-secret")); err != nil {
					t.Error(err)
				}
				return true
			}
		}, "auth", "invalid_response", http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			logs := &lockedBuffer{}
			f := newScopedFixtureLogged(t, nil, logs)
			tc.setup(f)
			w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", nil)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body)
			}
			records := w1FailureRecords(t, logs.String())
			if len(records) != 1 {
				t.Fatalf("%d failure records in %q", len(records), logs.String())
			}
			r := records[0]
			if r.RequestID != w.Header().Get("X-Request-ID") || r.RequestID == "" || r.Owner != tc.owner || r.Class != tc.class || r.Status != tc.status || r.Operation == "" || r.Restaurant != scopedRestaurant || r.DurationMS == nil {
				t.Fatalf("record %+v", r)
			}
			for _, secret := range []string{"session", "preauth", "auth-issued-token", "auth-body-secret", "owner-body-secret", "127.0.0.1", "192.0.2.", "csrf"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatalf("log leaks %q: %s", secret, logs.String())
				}
			}
		})
	}
}

func TestW1OwnersAreAskedForIdentityEncoding(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := summaryPage(scopedRestaurant, "stock", true)
		writeScopedJSON(t, w, map[string]any{"context": page["context"], "result": map[string]any{"items": page["items"]}})
	}
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", map[string]string{"Accept-Encoding": "gzip, br"})
	f.mu.Lock()
	defer f.mu.Unlock()
	if w.Code != http.StatusOK || len(f.requests) != 1 || f.requests[0].Header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("status %d, owner saw %v", w.Code, f.requests)
	}
}

// A sender that stops in the middle of a body is cut after UPSTREAM_TIMEOUT instead of holding the handler.
func TestW1StalledRequestBodyIsCutAfterUpstreamTimeout(t *testing.T) {
	f := newScopedFixtureWith(t, map[string]string{"UPSTREAM_TIMEOUT": "300ms"})
	server := httptest.NewServer(f.handler)
	t.Cleanup(server.Close)
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
	})
	if _, err := fmt.Fprintf(conn, "POST /api/v2/feedback/anonymous HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"sub"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(status, " 400 ") {
		t.Fatalf("status line %q: %v", status, err)
	}
	if elapsed := time.Since(started); elapsed < 250*time.Millisecond || elapsed > 4*time.Second {
		t.Fatalf("stalled body answered after %s, want about the 300ms timeout", elapsed)
	}
}
