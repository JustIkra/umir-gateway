package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestExpiredSessionCanBootstrapAnonymousCSRF(t *testing.T) {
	for _, path := range []string{"/api/v2/csrf", "/api/operator/csrf"} {
		t.Run(path, func(t *testing.T) {
			var calls atomic.Int32
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.URL.Path != "/internal/auth/v1/public/csrf" || r.Header.Get("X-Umir-Service-Key") != "auth-key" {
					t.Error("wrong Auth boundary")
				}
				w.Header().Set("Content-Type", "application/json")
				if n == 1 {
					if r.Header.Get("X-Umir-Session") != "synthetic-session" {
						t.Error("original session missing")
					}
					w.WriteHeader(http.StatusUnauthorized)
					if _, err := io.WriteString(w, `{"code":"Unauthenticated","outcome":"not_committed","message":"session expired","retryable":false}`); err != nil {
						t.Error(err)
					}
					return
				}
				if n != 2 || r.Header.Get("X-Umir-Session") != "" || r.Header.Get("Cookie") != "" {
					t.Error("anonymous retry retained an invalid session")
				}
				if _, err := io.WriteString(w, `{"csrfToken":"guest-csrf","preauthToken":"private-guest-context","expiresAt":"2099-10-13T10:00:00+03:00"}`); err != nil {
					t.Error(err)
				}
			}))
			w := facadeRequest(app, "GET", path, "")
			if w.Code != http.StatusOK || calls.Load() != 2 {
				t.Fatalf("bootstrap status=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body) != 1 || body["csrfToken"] != "guest-csrf" {
				t.Fatal("public result leaked or lost the anonymous CSRF projection")
			}
			response := w.Result()
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			var cleared, preauth bool
			for _, cookie := range response.Cookies() {
				if cookie.Name == "umir_operator_session" && cookie.Value == "" && cookie.MaxAge < 0 {
					cleared = true
				}
				if cookie.Name == "umir_operator_preauth" && cookie.Value == "private-guest-context" && cookie.HttpOnly {
					preauth = true
				}
			}
			if !cleared || !preauth {
				t.Fatal("expired session was not replaced by the anonymous browser context")
			}
		})
	}

}

func TestCSRFDoesNotDowngradeAnAuthFailureToAnonymous(t *testing.T) {
	for _, code := range []string{"AuthUnavailable", "AuthStorageUnavailable"} {
		t.Run(code, func(t *testing.T) {
			var calls atomic.Int32
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				if err := json.NewEncoder(w).Encode(map[string]any{"code": code, "outcome": "unavailable", "message": "unavailable", "retryable": true}); err != nil {
					t.Error(err)
				}
			}))
			w := facadeRequest(app, "GET", "/api/v2/csrf", "")
			if w.Code != http.StatusServiceUnavailable || calls.Load() != 1 || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("unavailable authority was retried or changed browser authority")
			}
		})
	}
}

func TestCSRFRecoveryIsBoundedAndPreservesAnActiveSession(t *testing.T) {
	for _, path := range []string{"/api/v2/csrf", "/api/operator/csrf"} {
		for _, active := range []bool{false, true} {
			t.Run(path+"/"+map[bool]string{true: "active", false: "invalid"}[active], func(t *testing.T) {
				var calls atomic.Int32
				app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					if active {
						if _, err := io.WriteString(w, `{"csrfToken":"active-session-csrf"}`); err != nil {
							t.Error(err)
						}
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
					if _, err := io.WriteString(w, `{"code":"Unauthenticated","outcome":"not_committed","message":"invalid","retryable":false}`); err != nil {
						t.Error(err)
					}
				}))
				w := facadeRequest(app, "GET", path, "")
				if active {
					if w.Code != http.StatusOK || calls.Load() != 1 || len(w.Header().Values("Set-Cookie")) != 0 {
						t.Fatal("active session was replaced")
					}
					return
				}
				if w.Code != http.StatusUnauthorized || calls.Load() != 2 {
					t.Fatal("anonymous bootstrap retry was not bounded")
				}
			})
		}
	}
}
