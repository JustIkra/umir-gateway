package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type g4Auth struct {
	mu    sync.Mutex
	code  string
	calls []map[string]string
}

func (a *g4Auth) set(code string) { a.mu.Lock(); defer a.mu.Unlock(); a.code = code }

func g4Server(t *testing.T) (*g4Auth, *httptest.Server) {
	t.Helper()
	a := &g4Auth{}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Umir-Service-Key") != "auth-key" {
			t.Error("missing private Auth key")
		}
		switch r.URL.Path {
		case "/internal/auth/v1/access-check":
			var input map[string]string
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			a.calls = append(a.calls, input)
			if a.code != "" {
				status := 403
				if a.code == "ScopeDeleted" {
					status = 410
				}
				if a.code == "AuthUnavailable" {
					status = 503
				}
				w.WriteHeader(status)
				writeScopedJSON(t, w, map[string]any{"code": a.code, "outcome": "unavailable", "message": "synthetic outcome", "retryable": false})
				return
			}
			writeScopedJSON(t, w, map[string]any{"orgID": scopedOrg, "restaurantID": input["restaurantID"], "roles": []string{"Warehouse"}, "orgRoles": []string{}, "permissions": []string{"stock.read"}, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "1"}, "lifecycleVersion": "1"})
		default:
			t.Errorf("unexpected Auth request %s", r.URL.Path)
			w.WriteHeader(503)
		}
	}))
	t.Cleanup(auth.Close)
	values := map[string]string{"AUTH_URL": auth.URL, "SERVING_URL": auth.URL, "WAREHOUSE_URL": auth.URL, "FEEDBACK_URL": auth.URL, "AUTH_SERVICE_KEY": "auth-key", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}
	app, err := componentsForTest(t, loadConfig(t, values), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app.handler)
	t.Cleanup(server.Close)
	return a, server
}

func g4Open(t *testing.T, server *httptest.Server, tenant, query, token string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, server.URL+"/api/v2/r/"+tenant+"/live"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(&http.Cookie{Name: "umir_operator_session", Value: token})
	response, err := (&http.Client{Timeout: 8 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	return response
}

func g4Frame(t *testing.T, reader *bufio.Reader) (string, string) {
	t.Helper()
	var name, data string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream read: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(line, "event: ") {
			name = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		}
		if line == "" && name != "" {
			return name, data
		}
	}
}

func TestG4StreamClosesOnCurrentAuthOutcome(t *testing.T) {
	for _, tc := range []struct{ code, reason string }{
		{"Forbidden", "revoked"}, {"ScopeDeleted", "deleted"}, {"Unauthenticated", "session-expired"}, {"AuthUnavailable", "auth-unavailable"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			t.Parallel()
			a, server := g4Server(t)
			response := g4Open(t, server, scopedRestaurant, "", "synthetic-session")
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			if response.StatusCode != 200 {
				t.Fatalf("live route=%d, want active scoped stream", response.StatusCode)
			}
			reader := bufio.NewReader(response.Body)
			name, data := g4Frame(t, reader)
			if name != "refresh-required" || !strings.Contains(data, scopedRestaurant) {
				t.Fatalf("greeting=%s %s", name, data)
			}
			a.set(tc.code)
			name, data = g4Frame(t, reader)
			if name != "access-ended" || !strings.Contains(data, `"reason":"`+tc.reason+`"`) {
				t.Fatalf("cutoff=%s %s", name, data)
			}
			if _, err := reader.ReadString('\n'); err != io.EOF {
				t.Fatalf("stream did not close: %v", err)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.calls) < 3 {
				t.Fatalf("missing revalidation: %v", a.calls)
			}
			for _, call := range a.calls {
				if call["operation"] != "live" || len(call) != 3 {
					t.Fatalf("SSE extended activity or minted token: %v", call)
				}
			}
		})
	}
}

func TestG4CursorSpoofDoesNotReplay(t *testing.T) {
	_, server := g4Server(t)
	response := g4Open(t, server, scopedRestaurant, "?cursor=browser-chosen", "synthetic-session")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != 403 {
		t.Fatalf("unknown cursor=%d, want 403 with no replay", response.StatusCode)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "event:") {
		t.Fatal("cursor replayed bytes")
	}
}

func TestG4ReconnectAfterGatewayRestartRequiresRefresh(t *testing.T) {
	_, server := g4Server(t)
	response := g4Open(t, server, scopedRestaurant, "", "synthetic-session")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != 200 {
		t.Fatalf("live route=%d", response.StatusCode)
	}
	name, data := g4Frame(t, bufio.NewReader(response.Body))
	var event struct {
		Epoch string `json:"epoch"`
	}
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		t.Fatal(err)
	}
	if name != "refresh-required" || event.Epoch == "" {
		t.Fatalf("initial=%s %s", name, data)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	_, second := g4Server(t)
	other := g4Open(t, second, scopedRestaurant, "", "synthetic-session")
	defer func() {
		if err := other.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	name, data = g4Frame(t, bufio.NewReader(other.Body))
	if name != "refresh-required" || strings.Contains(data, event.Epoch) {
		t.Fatalf("restart identity reused: %s %s", name, data)
	}
}

func TestG4BusinessRestartRefreshesScopedStream(t *testing.T) {
	f := newScopedFixture(t)
	epoch := scopedEpoch
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := summaryPage(scopedRestaurant, "stock", true)
		value, ok := page["context"].(map[string]any)
		if !ok {
			t.Error("context fixture")
			return
		}
		value["runtimeEpoch"] = epoch
		writeScopedJSON(t, w, map[string]any{"context": value, "result": map[string]any{"items": page["items"]}})
	}
	server := httptest.NewServer(f.handler)
	t.Cleanup(server.Close)
	response := g4Open(t, server, scopedRestaurant, "", "session")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != 200 {
		t.Fatalf("live route=%d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	g4Frame(t, reader)
	path := "/api/v2/r/" + scopedRestaurant + "/warehouse/inventory"
	if got := f.request("GET", path, "", nil); got.Code != 200 {
		t.Fatalf("initial inventory=%d %s", got.Code, got.Body)
	}
	epoch = "77777777-7777-4777-8777-777777777777"
	if got := f.request("GET", path, "", nil); got.Code != 200 {
		t.Fatalf("reset inventory=%d %s", got.Code, got.Body)
	}
	name, data := g4Frame(t, reader)
	if name != "refresh-required" || !strings.Contains(data, scopedRestaurant) {
		t.Fatalf("reset event=%s %s", name, data)
	}
}

func TestG4CommittedReadFailureStillInvalidates(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Umir-Invalidation-Required", "true")
		w.Header().Set("X-Umir-Committed-Version", "4")
		w.Header().Set("X-Umir-Runtime-Epoch", scopedEpoch)
		w.WriteHeader(503)
		writeScopedJSON(t, w, map[string]any{"code": "UpstreamUnavailable", "outcome": "unavailable", "message": "calculation failed after preparation", "retryable": false})
	}
	server := httptest.NewServer(f.handler)
	t.Cleanup(server.Close)
	response := g4Open(t, server, scopedRestaurant, "", "session")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != 200 {
		t.Fatalf("live route=%d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	g4Frame(t, reader)
	if got := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", nil); got.Code != 503 {
		t.Fatalf("read failure=%d", got.Code)
	}
	name, data := g4Frame(t, reader)
	if name != "change" || !strings.Contains(data, `"analytics"`) {
		t.Fatalf("committed preparation lost=%s %s", name, data)
	}
}

func TestG4KnownCursorAfterGatewayRestartIsRefreshAndRemainsBound(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Umir-Invalidation-Required", "true")
		w.Header().Set("X-Umir-Committed-Version", "4")
		w.Header().Set("X-Umir-Runtime-Epoch", scopedEpoch)
		w.WriteHeader(503)
		writeScopedJSON(t, w, map[string]any{"code": "UpstreamUnavailable", "outcome": "unavailable", "message": "synthetic failure", "retryable": false})
	}
	first := httptest.NewServer(f.handler)
	t.Cleanup(first.Close)
	response := g4Open(t, first, scopedRestaurant, "", "session")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != 200 {
		t.Fatalf("live=%d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	g4Frame(t, reader)
	f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", nil)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "id: ") {
		t.Fatalf("missing change id: %s", line)
	}
	cursor := strings.TrimSpace(strings.TrimPrefix(line, "id: "))
	g4Frame(t, reader)
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	second := newScopedFixture(t)
	restarted := httptest.NewServer(second.handler)
	t.Cleanup(restarted.Close)
	after := g4Open(t, restarted, scopedRestaurant, "?cursor="+cursor, "session")
	defer func() {
		if err := after.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if after.StatusCode != 200 {
		t.Fatalf("old legitimate cursor=%d, want refresh-required", after.StatusCode)
	}
	name, data := g4Frame(t, bufio.NewReader(after.Body))
	if name != "refresh-required" || !strings.Contains(data, scopedRestaurant) {
		t.Fatalf("restart=%s %s", name, data)
	}
	spoof := g4Open(t, restarted, scopedOtherRestaurant, "?cursor="+cursor, "session")
	defer func() {
		if err := spoof.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if spoof.StatusCode != 403 {
		t.Fatalf("old cross-scope cursor=%d", spoof.StatusCode)
	}
	spoof = g4Open(t, restarted, scopedRestaurant, "?cursor="+cursor, "another-user")
	defer func() {
		if err := spoof.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if spoof.StatusCode != 403 {
		t.Fatalf("old cross-actor cursor=%d", spoof.StatusCode)
	}
}

func TestG4MalformedRejectionStillInvalidatesUnknownMutation(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		if _, err := io.WriteString(w, `{"invalid":"not an owner refusal"}`); err != nil {
			t.Error(err)
		}
	}
	server := httptest.NewServer(f.handler)
	t.Cleanup(server.Close)
	response := g4Open(t, server, scopedRestaurant, "", "session")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != 200 {
		t.Fatalf("live=%d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	g4Frame(t, reader)
	result := f.request("POST", "/api/v2/r/"+scopedRestaurant+"/warehouse/products", `{"commandID":"saved","productID":"P1","name":"Product","baseUnit":"g"}`, nil)
	if result.Code != 502 || !strings.Contains(result.Body.String(), `"outcome":"unknown"`) {
		t.Fatalf("invalid refusal became definite=%d %s", result.Code, result.Body)
	}
	name, data := g4Frame(t, reader)
	if name != "change" || !strings.Contains(data, scopedRestaurant) {
		t.Fatalf("unknown mutation lost invalidation=%s %s", name, data)
	}
}
