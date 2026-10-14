package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/authclient"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

type repairTransport func(*http.Request) (*http.Response, error)

func (f repairTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type repairBusiness struct{ calls int }

func (b *repairBusiness) Do(_ context.Context, _ httpapi.BusinessRequest) (httpapi.BusinessResponse, error) {
	b.calls++
	return httpapi.BusinessResponse{}, nil
}

func TestG2RepairAuthRateLimitMetadata(t *testing.T) {
	for _, stage := range []string{"csrf", "authorize"} {
		for _, metadata := range []struct {
			name, header, body string
			status             int
		}{
			{"valid", "60", `{"retryAfterSeconds":60}`, 429},
			{"details_only", "", `{"retryAfterSeconds":60}`, 429},
			{"conflicting_delay", "61", `{"retryAfterSeconds":60}`, 503},
			{"invalid_delay", "060", `{"retryAfterSeconds":60}`, 503},
			{"missing_delay", "", `{}`, 503},
		} {
			t.Run(stage+"/"+metadata.name, func(t *testing.T) {
				u, err := url.Parse("http://127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				client, err := authclient.New(authclient.Options{URL: u, ServiceKey: "synthetic", Timeout: time.Second, Transport: repairTransport(func(r *http.Request) (*http.Response, error) {
					if !strings.HasSuffix(r.URL.Path, "/"+stage) {
						t.Fatalf("unexpected Auth call: %s", r.URL.Path)
					}
					return &http.Response{StatusCode: 429, Header: http.Header{"Content-Type": []string{"application/json"}, "Retry-After": []string{metadata.header}}, Body: io.NopCloser(strings.NewReader(`{"code":"RateLimited","outcome":"not_committed","message":"capacity exhausted","retryable":true,"details":` + metadata.body + `}`))}, nil
				})})
				if err != nil {
					t.Fatal(err)
				}
				business := &repairBusiness{}
				api, err := httpapi.NewScoped(httpapi.ScopedOptions{Auth: client, Business: business, Origin: testOrigin, Now: time.Now, Logger: log.New(io.Discard, "", 0)})
				if err != nil {
					t.Fatal(err)
				}
				method, path, body := "GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", ""
				if stage == "csrf" {
					method, path, body = "POST", "/api/v2/r/"+scopedRestaurant+"/warehouse/products", `{"commandID":"same","productID":"P","name":"A","baseUnit":"g"}`
				}
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: "umir_operator_session", Value: "session"})
				if method == "POST" {
					r.Header.Set("Origin", testOrigin)
					r.Header.Set("X-CSRF-Token", "csrf")
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("X-Umir-Runtime-Epoch", scopedEpoch)
				}
				w := httptest.NewRecorder()
				api.ServeHTTP(w, r)
				var result struct {
					Code      string
					Retryable bool
					Details   struct{ RetryAfterSeconds int }
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				t.Logf("status=%d retry-after=%q body=%s business-calls=%d", w.Code, w.Header().Get("Retry-After"), w.Body.String(), business.calls)
				if w.Code != metadata.status || business.calls != 0 {
					t.Fatalf("status=%d want=%d business calls=%d", w.Code, metadata.status, business.calls)
				}
				if metadata.status == 429 && (w.Header().Get("Retry-After") != "60" || !result.Retryable || result.Details.RetryAfterSeconds != 60) {
					t.Fatalf("Auth rate-limit metadata was not preserved")
				}
				if metadata.status == 503 && (w.Header().Get("Retry-After") != "" || result.Code != "AuthUnavailable") {
					t.Fatalf("invalid Auth metadata was forwarded")
				}
			})
		}
	}
}

func TestG2RepairServingSavedEpoch(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "same_epoch_control", true: "different_epoch"}[mismatch], func(t *testing.T) {
			f := newScopedFixture(t)
			f.peer = func(w http.ResponseWriter, r *http.Request) {
				ctx, ok := summaryPage(scopedRestaurant, "stock", true)["context"].(map[string]any)
				if !ok {
					t.Fatal("missing Serving context fixture")
				}
				ctx["warehouseEpoch"] = scopedEpoch
				if mismatch {
					ctx["runtimeEpoch"] = "99999999-9999-4999-8999-999999999999"
				}
				value := map[string]any{"context": ctx, "result": map[string]any{"kind": "EmptyOrder"}}
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := httpapi.ValidateScopeWire("ServingScopedConfirmResult", data); err != nil {
					t.Fatal(err)
				}
				w.Header().Set("Content-Type", "application/json")
				writeScopedJSON(t, w, value)
			}
			w := f.request("POST", "/api/v2/r/"+scopedRestaurant+"/serving/order-confirmations", `{"commandID":"saved","proposalID":"proposal"}`, nil)
			t.Logf("status=%d response=%s", w.Code, w.Body.String())
			if !mismatch && w.Code != 200 {
				t.Fatalf("valid same-epoch control refused")
			}
			if mismatch && (w.Code != 502 || !strings.Contains(w.Body.String(), `"outcome":"unknown"`)) {
				t.Fatalf("different Serving epoch was accepted as an authoritative terminal outcome")
			}
		})
	}
}

func TestG2RepairErrorScope(t *testing.T) {
	for _, scope := range []string{scopedRestaurant, scopedOrg, "99999999-9999-4999-8999-999999999999"} {
		t.Run(scope, func(t *testing.T) {
			mismatch := scope != scopedRestaurant && scope != scopedOrg
			f := newScopedFixture(t)
			f.peer = func(w http.ResponseWriter, r *http.Request) {
				value := map[string]any{"code": "ScopeDeleted", "outcome": "unavailable", "message": "deleted", "retryable": false, "details": map[string]any{"scopeID": scope}}
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := httpapi.ValidateScopeWire("Error", data); err != nil {
					t.Fatal(err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(410)
				writeScopedJSON(t, w, value)
			}
			w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", nil)
			t.Logf("status=%d response=%s", w.Code, w.Body.String())
			if !mismatch && w.Code != 410 {
				t.Fatalf("valid same-scope error refused")
			}
			if mismatch && (w.Code != 502 || strings.Contains(w.Body.String(), "99999999-9999-4999-8999-999999999999")) {
				t.Fatalf("foreign scope error was exposed")
			}
		})
	}
}

type repairBusinessFunc func(context.Context, httpapi.BusinessRequest) (httpapi.BusinessResponse, error)

func (f repairBusinessFunc) Do(ctx context.Context, r httpapi.BusinessRequest) (httpapi.BusinessResponse, error) {
	return f(ctx, r)
}

func TestG2RepairResolveServingSavedEpoch(t *testing.T) {
	for _, reply := range []string{"same_epoch_control", "different_epoch", "runtime_reset"} {
		t.Run(reply, func(t *testing.T) {
			mismatch := reply == "different_epoch"
			u, err := url.Parse("http://127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			decision := httpapi.AuthorizationResult{UserID: "11111111-1111-4111-8111-111111111111", SessionID: "55555555-5555-4555-8555-555555555555", SessionVersion: "1", CredentialVersion: "1", AccessVersion: "1", OrgID: scopedOrg, TenantID: scopedRestaurant, Permissions: []string{"order.read"}, Settings: httpapi.ScopeSettings{TimeZone: "Europe/Moscow", SettingsVersion: "2"}, LifecycleVersion: "1", Token: "synthetic-token", ExpiresAt: now.Add(time.Minute), Session: httpapi.ScopeSession{ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour), CSRFToken: "csrf"}}
			data, err := json.Marshal(decision)
			if err != nil {
				t.Fatal(err)
			}
			client, err := authclient.New(authclient.Options{URL: u, ServiceKey: "synthetic", Timeout: time.Second, Transport: repairTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			query := "commandID=saved&proposalID=proposal&runtimeEpoch=" + scopedEpoch
			reset := `{"code":"RuntimeReset","outcome":"indeterminate","message":"runtime reset","retryable":false,"details":{"expectedEpoch":"` + scopedEpoch + `","currentEpoch":"99999999-9999-4999-8999-999999999999","scopeID":"` + scopedRestaurant + `"}}`
			business := repairBusinessFunc(func(_ context.Context, r httpapi.BusinessRequest) (httpapi.BusinessResponse, error) {
				calls++
				if r.RawQuery != query {
					t.Fatal("saved epoch query was not forwarded")
				}
				if reply == "runtime_reset" {
					if err := httpapi.ValidateScopeWire("Error", []byte(reset)); err != nil {
						t.Fatal(err)
					}
					return httpapi.BusinessResponse{Status: 409, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(reset)}, nil
				}
				ctx, ok := summaryPage(scopedRestaurant, "stock", true)["context"].(map[string]any)
				if !ok {
					t.Fatal("missing Serving context fixture")
				}
				ctx["warehouseEpoch"] = scopedEpoch
				if mismatch {
					ctx["runtimeEpoch"] = "99999999-9999-4999-8999-999999999999"
				}
				body, err := json.Marshal(map[string]any{"context": ctx, "result": map[string]any{"kind": "EmptyOrder"}})
				if err != nil {
					t.Fatal(err)
				}
				if err := httpapi.ValidateScopeWire("ServingScopedConfirmResult", body); err != nil {
					t.Fatal(err)
				}
				return httpapi.BusinessResponse{Status: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, nil
			})
			api, err := httpapi.NewScoped(httpapi.ScopedOptions{Auth: client, Business: business, Origin: testOrigin, Now: time.Now, Logger: log.New(io.Discard, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/api/v2/r/"+scopedRestaurant+"/serving/order-confirmations/resolve?"+query, nil)
			r.AddCookie(&http.Cookie{Name: "umir_operator_session", Value: "session"})
			w := httptest.NewRecorder()
			api.ServeHTTP(w, r)
			t.Logf("status=%d response=%s business-calls=%d", w.Code, w.Body.String(), calls)
			if reply == "same_epoch_control" && (w.Code != 200 || calls != 1) {
				t.Fatalf("valid same-epoch control refused")
			}
			if mismatch && (w.Code != 502 || !strings.Contains(w.Body.String(), `"outcome":"unavailable"`)) {
				t.Fatalf("different Serving epoch resolved the saved attempt as a terminal outcome")
			}
			if reply == "runtime_reset" && (w.Code != 409 || w.Body.String() != reset || calls != 1) {
				t.Fatalf("authoritative runtime reset was not preserved")
			}
		})
	}
}
