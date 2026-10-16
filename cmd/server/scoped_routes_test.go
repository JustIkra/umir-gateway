package main

import (
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

const scopedRestaurant = "33333333-3333-4333-8333-333333333333"
const scopedOtherRestaurant = "66666666-6666-4666-8666-666666666666"
const scopedOrg = "22222222-2222-4222-8222-222222222222"
const scopedEpoch = "44444444-4444-4444-8444-444444444444"

type capturedScoped struct {
	Path, Query, Body, Method string
	Header                    http.Header
}

type scopedFixture struct {
	mu             sync.Mutex
	authorizations []map[string]any
	requests       []capturedScoped
	deny           bool
	wrongTenant    bool
	peer           func(http.ResponseWriter, *http.Request)
	handler        http.Handler
	// anonymousTokens counts the anonymous feedback tokens Auth issued.
	anonymousTokens int
	// authRequestIDs are the X-Request-ID values Auth saw; authHook may take over an Auth request.
	authRequestIDs []string
	authHook       func(http.ResponseWriter, *http.Request) bool
}

func newScopedFixture(t *testing.T, closeFailure ...bool) *scopedFixture {
	t.Helper()
	return newScopedFixtureWith(t, nil, closeFailure...)
}

// newScopedFixtureWith adds settings to the Gateway configuration.
func newScopedFixtureWith(t *testing.T, extra map[string]string, closeFailure ...bool) *scopedFixture {
	t.Helper()
	return newScopedFixtureLogged(t, extra, io.Discard, closeFailure...)
}

// newScopedFixtureLogged also sends the Gateway log to logs.
func newScopedFixtureLogged(t *testing.T, extra map[string]string, logs io.Writer, closeFailure ...bool) *scopedFixture {
	t.Helper()
	f := &scopedFixture{}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		f.authRequestIDs = append(f.authRequestIDs, r.Header.Get("X-Request-ID"))
		if f.authHook != nil && f.authHook(w, r) {
			return
		}
		if r.Header.Get("X-Umir-Service-Key") != "auth-key" {
			t.Error("wrong Auth key")
		}
		switch r.URL.Path {
		case "/internal/auth/v1/public/csrf":
			writeScopedJSON(t, w, map[string]any{"csrfToken": "csrf"})
		case "/internal/auth/v1/anonymous-feedback-token":
			f.anonymousTokens++
			writeScopedJSON(t, w, map[string]any{"token": "anonymous-token", "expiresAt": time.Now().Add(time.Minute).Format(time.RFC3339Nano)})
		case "/internal/auth/v1/access-check", "/internal/auth/v1/authorize":
			var input map[string]any
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			f.authorizations = append(f.authorizations, input)
			if f.deny {
				w.WriteHeader(403)
				writeScopedJSON(t, w, map[string]any{"code": "Forbidden", "outcome": "not_committed", "message": "denied", "retryable": false})
				return
			}
			tenant, ok := input["restaurantID"].(string)
			if !ok {
				t.Fatal("restaurantID is missing")
			}
			if f.wrongTenant {
				tenant = scopedOtherRestaurant
			}
			settings := map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "2"}
			if r.URL.Path == "/internal/auth/v1/access-check" {
				writeScopedJSON(t, w, map[string]any{"orgID": scopedOrg, "restaurantID": tenant, "roles": []string{}, "orgRoles": []string{"Admin"}, "permissions": []string{"org.summary.read"}, "settings": settings, "lifecycleVersion": "1"})
				return
			}
			permissions := []string{"catalog.read", "catalog.write", "stock.read", "menu.read", "order.confirm", "feedback.submit", "feedback.read", "feedback.export", "analytics.read", "writeoff.confirm"}
			if input["operation"] == "recommendations" {
				permissions = []string{"recommendations.read", "consumer.recommendations.read"}
			}
			writeScopedJSON(t, w, map[string]any{"userID": "11111111-1111-4111-8111-111111111111", "sessionID": "55555555-5555-4555-8555-555555555555", "sessionVersion": "1", "credentialVersion": "1", "accessVersion": "1", "orgID": scopedOrg, "tenantID": tenant, "permissions": permissions, "settings": settings, "lifecycleVersion": "1", "token": "auth-issued-token", "expiresAt": time.Now().Add(time.Minute).Format(time.RFC3339Nano), "session": map[string]any{"expiresAt": "2099-10-13T10:00:00+03:00", "idleExpiresAt": "2099-10-13T10:00:00+03:00", "absoluteExpiresAt": "2099-10-13T11:00:00+03:00", "rememberMe": false, "csrfToken": "csrf"}})
		default:
			t.Errorf("unexpected Auth path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(auth.Close)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		f.mu.Lock()
		f.requests = append(f.requests, capturedScoped{r.URL.Path, r.URL.RawQuery, string(body), r.Method, r.Header.Clone()})
		handler := f.peer
		f.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		writeScopedJSON(t, w, map[string]any{"code": "CommandConflict", "outcome": "not_committed", "message": "owner refusal", "retryable": false})
	}))
	t.Cleanup(peer.Close)
	values := map[string]string{"AUTH_URL": auth.URL, "AUTH_SERVICE_KEY": "auth-key", "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}
	for key, value := range extra {
		values[key] = value
	}
	app, err := componentsForTest(t, loadConfig(t, values), log.New(logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	f.handler = app.handler
	if len(closeFailure) != 0 && closeFailure[0] {
		f.handler = g4CloseFailureHandler(t, loadConfig(t, values))
	}
	return f
}

func writeScopedJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}

func (f *scopedFixture) request(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "umir_operator_session", Value: "session"})
	r.AddCookie(&http.Cookie{Name: "umir_operator_preauth", Value: "preauth"})
	if method == http.MethodPost {
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("X-CSRF-Token", "csrf")
		r.Header.Set("Content-Type", "application/json")
		if strings.Contains(path, "/warehouse/") || strings.Contains(path, "/serving/") {
			r.Header.Set("X-Umir-Runtime-Epoch", scopedEpoch)
		}
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func TestG2ScopedDispatchPreservesOwnerInputAndRechecksAccess(t *testing.T) {
	f := newScopedFixture(t)
	path := "/api/v2/r/" + scopedRestaurant + "/warehouse/products"
	body := `{ "commandID":"same", "productID":"01", "name":"Exact", "baseUnit":"g" }`
	w := f.request("POST", path, body, map[string]string{"X-User-ID": "spoof", "X-Tenant-ID": scopedOtherRestaurant, "X-Role": "Admin"})
	if w.Code != 409 || len(f.requests) != 1 {
		t.Fatalf("dispatch = %d %s requests=%d", w.Code, w.Body, len(f.requests))
	}
	got := f.requests[0]
	if got.Body != body || got.Path != "/internal/warehouse/v2/r/"+scopedRestaurant+"/products" || got.Header.Get("Authorization") != "Bearer auth-issued-token" || got.Header.Get("X-Umir-Service-Key") != "warehouse-key" || got.Header.Get("X-Umir-Runtime-Epoch") != scopedEpoch {
		t.Fatalf("forwarded input=%+v", got)
	}
	for _, key := range []string{"Cookie", "X-CSRF-Token", "X-User-ID", "X-Tenant-ID", "X-Role"} {
		if got.Header.Get(key) != "" {
			t.Errorf("leaked %s", key)
		}
	}
	if len(f.authorizations) != 1 || f.authorizations[0]["operation"] != "registerProduct" {
		t.Fatalf("authorization=%v", f.authorizations)
	}
	f.deny = true
	w = f.request("POST", path, body, nil)
	if w.Code != 403 || len(f.requests) != 1 {
		t.Fatalf("revoked dispatch=%d requests=%d", w.Code, len(f.requests))
	}
}

func TestG2WaiterServingCannotDispatchWarehouse(t *testing.T) {
	f := newScopedFixture(t)
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/serving/menu", "", nil)
	if w.Code != 409 || len(f.requests) != 1 {
		t.Fatalf("Serving route=%d %s", w.Code, w.Body)
	}
	a := f.authorizations[0]
	aud, err := json.Marshal(a["audiences"])
	if err != nil {
		t.Fatal(err)
	}
	if string(aud) != `["umir-serving","umir-warehouse"]` || a["operation"] != "menu" {
		t.Fatalf("consumer mapping=%v", a)
	}
	f.deny = true
	w = f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", nil)
	if w.Code != 403 || len(f.requests) != 1 {
		t.Fatalf("Warehouse escalation=%d requests=%d", w.Code, len(f.requests))
	}
}

func TestG2SpoofMalformedAndMissingMappingsDoNotDispatch(t *testing.T) {
	for _, tc := range []struct {
		name, method, suffix, body string
		headers                    map[string]string
		status                     int
	}{
		{"body tenant", "POST", "warehouse/products", `{"commandID":"a","productID":"P","name":"A","baseUnit":"g","tenantID":"` + scopedOtherRestaurant + `"}`, nil, 400},
		{"query tenant", "GET", "warehouse/inventory?tenantID=" + scopedOtherRestaurant, "", nil, 400},
		{"duplicate query", "GET", "warehouse/dish?dishID=A&dishID=B", "", nil, 400},
		{"unmapped route", "GET", "warehouse/order-commits", "", nil, 404},
		{"internal credentials", "GET", "warehouse/inventory", "", map[string]string{"Authorization": "Bearer browser"}, 403},
		{"missing csrf", "POST", "warehouse/products", `{"commandID":"a","productID":"P","name":"A","baseUnit":"g"}`, map[string]string{"X-CSRF-Token": ""}, 403},
		{"bad epoch", "POST", "warehouse/products", `{"commandID":"a","productID":"P","name":"A","baseUnit":"g"}`, map[string]string{"X-Umir-Runtime-Epoch": "*"}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newScopedFixture(t)
			w := f.request(tc.method, "/api/v2/r/"+scopedRestaurant+"/"+tc.suffix, tc.body, tc.headers)
			if w.Code != tc.status || len(f.requests) != 0 {
				t.Fatalf("refusal=%d %s dispatch=%d", w.Code, w.Body, len(f.requests))
			}
		})
	}
}

func TestG2RejectsInconsistentAuthTenant(t *testing.T) {
	f := newScopedFixture(t)
	f.wrongTenant = true
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", nil)
	if w.Code != 503 || len(f.requests) != 0 {
		t.Fatalf("tenant mismatch=%d requests=%d", w.Code, len(f.requests))
	}
}

func TestG2RetainedSettingsReachOwnerUnchanged(t *testing.T) {
	f := newScopedFixture(t)
	query := "expectedSettingsVersion=1&riskHours=48"
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/analytics/stock?"+query, "", nil)
	if w.Code != 409 || len(f.requests) != 1 || f.requests[0].Query != query {
		t.Fatalf("owner settings input=%d requests=%v", w.Code, f.requests)
	}
}

func TestG2FeedbackTrustedAndAnonymousContexts(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		t.Run(map[bool]string{false: "app", true: "anonymous"}[anonymous], func(t *testing.T) {
			f := newScopedFixture(t)
			path := "/api/v2/r/" + scopedRestaurant + "/feedback"
			if anonymous {
				path = "/api/v2/feedback/anonymous"
			}
			body := `{"submissionID":"77777777-7777-4777-8777-777777777777","name":"A","email":"a@example.test","message":"M","consent":{"accepted":true,"documentVersion":"1"}}`
			w := f.request("POST", path, body, map[string]string{"X-Org-ID": "spoof"})
			if w.Code != 409 || len(f.requests) != 1 {
				t.Fatalf("feedback=%d %s", w.Code, w.Body)
			}
			got := f.requests[0]
			if got.Header.Get("X-Org-ID") != "" || got.Header.Get("Cookie") != "" || got.Header.Get("X-Umir-Service-Key") != "feedback-key" {
				t.Fatalf("feedback credentials=%v", got.Header)
			}
			if anonymous {
				if got.Body != body || got.Path != "/internal/feedback/v2/submissions/anonymous" || strings.Contains(got.Body, "tenantID") {
					t.Fatalf("anonymous=%+v", got)
				}
			} else {
				var envelope struct {
					Submission json.RawMessage                                `json:"submission"`
					Context    struct{ Kind, UserID, OrgID, TenantID string } `json:"context"`
				}
				if err := json.Unmarshal([]byte(got.Body), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.Context.TenantID != scopedRestaurant || envelope.Context.OrgID != scopedOrg || envelope.Context.Kind != "app" {
					t.Fatalf("trusted context=%+v", envelope)
				}
			}
		})
	}
}
