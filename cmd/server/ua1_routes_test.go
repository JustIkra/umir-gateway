package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestUA1AuthFacadeExecutableComposition(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/orgs/" + scopedOrg + "/members?limit=1", ""},
		{"GET", "/orgs/" + scopedOrg + "/invitations?state=all", ""},
		{"POST", "/orgs/" + scopedOrg + "/invitations/77777777-7777-4777-8777-777777777777/resend-link", `{"commandID":"original-link-command"}`},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			calls := 0
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method || r.URL.RequestURI() != "/internal/auth/v1/public"+tc.path || r.Header.Get("X-Umir-Service-Key") != "auth-key" || r.Header.Get("X-Umir-Session") != "synthetic-session" || r.Header.Get("Cookie") != "" {
					t.Error("UA1 forwarding lost caller/session/path identity")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.body {
					t.Error("retained UA1 body changed")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(503)
				if _, err := io.WriteString(w, `{"code":"AuthStorageUnavailable","outcome":"not_committed","message":"storage refused","retryable":false}`); err != nil {
					t.Error(err)
				}
			}))
			w := facadeRequest(app, tc.method, "/api/v2"+tc.path, tc.body)
			if w.Code != 503 || calls != 1 || !strings.Contains(w.Body.String(), "AuthStorageUnavailable") {
				t.Fatalf("UA1 composition: status%d calls%d", w.Code, calls)
			}
		})
	}
}

func TestUA1ProductBatchForwardingAndIdentity(t *testing.T) {
	f := newScopedFixture(t)
	product := "P"
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/internal/warehouse/v2/r/"+scopedRestaurant+"/products/"+product+"/batches" || r.URL.RawQuery != "limit=1" {
			t.Error("nested product identity or query lost")
		}
		writeScopedJSON(t, w, map[string]any{
			"context": map[string]any{"orgID": scopedOrg, "tenantID": scopedRestaurant, "runtimeEpoch": scopedEpoch, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "2"}, "evaluatedAt": "2026-10-14T15:00:00+03:00", "stateVersion": "4"},
			"result":  map[string]any{"productID": product, "evaluatedAt": "2026-10-14T15:00:00+03:00", "page": map[string]any{"tenantID": scopedRestaurant, "epoch": scopedEpoch, "stateVersion": "4", "prefixSequence": "4", "filterFingerprint": strings.Repeat("a", 64), "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "2"}}, "items": []any{}},
		})
	}
	path := ""
	for _, id := range []string{"P", "паста #1", "товар%2F"} {
		product = id
		path = "/api/v2/r/" + scopedRestaurant + "/warehouse/products/" + url.PathEscape(id) + "/batches?limit=1"
		if w := f.request("GET", path, "", nil); w.Code != 200 {
			t.Fatalf("batch composition unavailable: %d %s", w.Code, w.Body)
		}
	}
	if w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/products/group%2Fproduct/batches", "", nil); w.Code != 400 {
		t.Fatalf("encoded slash admitted: %d", w.Code)
	}
	f.peer = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeScopedJSON(t, w, map[string]any{
			"context": map[string]any{"orgID": scopedOrg, "tenantID": scopedRestaurant, "runtimeEpoch": scopedEpoch, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "2"}, "evaluatedAt": "2026-10-14T15:00:00+03:00", "stateVersion": "4"},
			"result":  map[string]any{"productID": "another-product", "evaluatedAt": "2026-10-14T15:00:00+03:00", "page": map[string]any{"tenantID": scopedRestaurant, "epoch": scopedEpoch, "stateVersion": "5", "prefixSequence": "5", "filterFingerprint": strings.Repeat("a", 64), "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "2"}}, "items": []any{}},
		})
	}
	if w := f.request("GET", path, "", nil); w.Code != 502 {
		t.Fatalf("different product/capture identity passed: %d", w.Code)
	}
}
