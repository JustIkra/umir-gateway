package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authFacadeHandler(t *testing.T, peer http.Handler) http.Handler {
	t.Helper()
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	values := map[string]string{"AUTH_URL": server.URL, "AUTH_SERVICE_KEY": "auth-key", "AUTH_ISOLATED_TEST_NETWORK": "true", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}
	app, err := newComponents(loadConfig(t, values), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return app.handler
}

func facadeRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "umir_operator_session", Value: "synthetic-session"})
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("X-CSRF-Token", "synthetic-csrf")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestAuthFacadeComposition(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/access", ""},
		{"GET", "/orgs/" + scopedOrg, ""},
		{"POST", "/orgs", `{"commandID":"same","name":"Test","timeZone":"Europe/Moscow","firstRestaurantName":"Test"}`},
		{"POST", "/sessions/logout-all", `{"commandID":"same"}`},
		{"GET", "/commands?namespace=profile.displayName&commandID=retained%2F%CE%B1", ""},
		{"POST", "/email-challenges", `{"commandID":"same","email":"synthetic@example.invalid","purpose":"login"}`},
		{"POST", "/orgs/" + scopedOrg + "/invitations", `{"commandID":"same","email":"synthetic@example.invalid","assignments":[{"restaurantID":"` + scopedRestaurant + `","roles":["Waiter"]}]}`},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			calls := 0
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method || r.URL.RequestURI() != "/internal/auth/v1/public"+tc.path || r.Header.Get("X-Umir-Service-Key") != "auth-key" || r.Header.Get("X-Umir-Session") != "synthetic-session" || r.Header.Get("Cookie") != "" {
					t.Errorf("wrong Auth request method=%s path=%s", r.Method, r.URL.RequestURI())
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.body {
					t.Error("retained payload changed")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(503)
				if _, err := io.WriteString(w, `{"code":"AuthStorageUnavailable","outcome":"not_committed","message":"storage refused","retryable":false}`); err != nil {
					t.Error(err)
				}
			}))
			w := facadeRequest(app, tc.method, "/api/v2"+tc.path, tc.body)
			if w.Code != 503 || calls != 1 || !strings.Contains(w.Body.String(), "AuthStorageUnavailable") {
				t.Fatalf("status=%d calls=%d response=%s", w.Code, calls, w.Body.String())
			}
		})
	}
}

func TestAuthFacadeRejectsAmbiguousCookies(t *testing.T) {
	calls := 0
	app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(503) }))
	r := httptest.NewRequest("GET", "/api/v2/me", nil)
	r.Header.Set("Cookie", "umir_operator_session=one; umir_operator_session=two")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 403 || calls != 0 {
		t.Fatalf("ambiguous cookies: status=%d calls=%d", w.Code, calls)
	}
}

func TestAuthFacadeRejectsInvalidBoundaryInput(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		headers                  map[string]string
		status                   int
	}{
		{"unknown query", "GET", "/access?tenantID=other", "", nil, 400},
		{"duplicate lookup", "GET", "/commands?namespace=one&namespace=two&commandID=same", "", nil, 400},
		{"lookup missing parameter", "GET", "/commands?namespace=one", "", nil, 400},
		{"invalid path", "GET", "/orgs/not-uuid", "", nil, 400},
		{"encoded path", "GET", "/orgs/%32" + scopedOrg[1:], "", nil, 400},
		{"unexpected body", "GET", "/access", `{}`, nil, 400},
		{"duplicate nested property", "POST", "/orgs/" + scopedOrg + "/invitations", `{"commandID":"same","email":"test@example.invalid","assignments":[{"restaurantID":"` + scopedRestaurant + `","roles":["Waiter"],"roles":["Warehouse"]}]}`, nil, 400},
		{"unknown field", "POST", "/email-challenges", `{"commandID":"same","email":"test@example.invalid","purpose":"login","token":"injected"}`, nil, 400},
		{"null", "POST", "/email-challenges", `{"commandID":"same","email":null,"purpose":"login"}`, nil, 400},
		{"path body mismatch", "POST", "/challenges/" + scopedOrg + "/verify", `{"commandID":"same","challengeID":"` + scopedRestaurant + `","code":"123456"}`, nil, 400},
		{"origin", "POST", "/sessions/logout-all", `{"commandID":"same"}`, map[string]string{"Origin": "https://foreign.invalid"}, 403},
		{"csrf", "POST", "/sessions/logout-all", `{"commandID":"same"}`, map[string]string{"X-CSRF-Token": ""}, 403},
		{"internal credential", "GET", "/access", "", map[string]string{"Authorization": "Bearer browser"}, 403},
		{"proxy credential", "GET", "/access", "", map[string]string{"Proxy-Authorization": "Basic browser"}, 403},
		{"unsupported method", "PUT", "/access", "", nil, 405},
		{"unknown route", "GET", "/registry", "", nil, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(503) }))
			r := httptest.NewRequest(tc.method, "/api/v2"+tc.path, strings.NewReader(tc.body))
			r.AddCookie(&http.Cookie{Name: "umir_operator_session", Value: "session"})
			r.Header.Set("Origin", testOrigin)
			r.Header.Set("X-CSRF-Token", "csrf")
			r.Header.Set("Content-Type", "application/json")
			for key, value := range tc.headers {
				r.Header.Set(key, value)
			}
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			if w.Code != tc.status || calls != 0 {
				t.Fatalf("status=%d want=%d Auth calls=%d", w.Code, tc.status, calls)
			}
		})
	}
}

func TestAuthFacadeProjectsIssuedCredentials(t *testing.T) {
	for _, tc := range []struct{ path, body string }{
		{"/session", `{"commandID":"same","login":"test","password":"password","rememberMe":true}`},
		{"/challenges/" + scopedOrg + "/complete", `{"commandID":"same","challengeID":"` + scopedOrg + `","proof":"proof","password":"password","displayName":"Test User"}`},
		{"/email-challenges/" + scopedOrg + "/complete", `{"commandID":"same","challengeID":"` + scopedOrg + `","proof":"proof","purpose":"login","rememberMe":true}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := io.WriteString(w, `{"view":{"user":{"userID":"11111111-1111-4111-8111-111111111111","login":"test","displayName":"Test User","credentialVersion":"1"},"session":{"expiresAt":"2099-10-13T10:00:00+03:00","idleExpiresAt":"2099-10-13T10:00:00+03:00","absoluteExpiresAt":"2099-10-13T10:00:00+03:00","rememberMe":true,"csrfToken":"csrf"}},"sessionToken":"private-session-token"}`); err != nil {
					t.Error(err)
				}
			}))
			w := facadeRequest(app, "POST", "/api/v2"+tc.path, tc.body)
			if w.Code != 200 || strings.Contains(w.Body.String(), "private-session-token") || strings.Contains(w.Body.String(), "sessionToken") {
				t.Fatalf("credential projection failed: status=%d", w.Code)
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Value != "private-session-token" || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].MaxAge <= 0 {
				t.Fatal("issued session did not become a persistent protected cookie")
			}
		})
	}
}

func TestAuthFacadeRejectsInvalidOwnerResponses(t *testing.T) {
	for _, body := range []string{
		`{"organizations":[],"restaurants":[],"memberships":[],"sessionToken":"leak"}`,
		`{"organizations":[],"restaurants":[],"memberships":null}`,
		`{"organizations":[],"restaurants":[],"memberships":[],"memberships":[]}`,
		`{"organizations":[{"orgID":"not-a-uuid"}],"restaurants":[],"memberships":[]}`,
		`{"organizations":[],"restaurants":[],"memberships":[]} {}`,
	} {
		t.Run(body, func(t *testing.T) {
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := io.WriteString(w, body); err != nil {
					t.Error(err)
				}
			}))
			w := facadeRequest(app, "GET", "/api/v2/access", "")
			if w.Code != 503 || !strings.Contains(w.Body.String(), `"outcome":"unavailable"`) || strings.Contains(w.Body.String(), "leak") {
				t.Fatalf("invalid upstream leaked: status=%d", w.Code)
			}
		})
	}
}

func TestAuthFacadePreservesOwnerErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{409, `{"code":"LastAdmin","outcome":"not_committed","message":"last admin","retryable":false}`},
		{429, `{"code":"RateLimited","outcome":"not_committed","message":"cooldown","retryable":false}`},
		{400, `{"code":"InvalidArgument","outcome":"committed","message":"wrong OTP counted","retryable":false}`},
		{503, `{"code":"AuthUpdateOutcomeUnknown","outcome":"unknown","message":"unknown","retryable":false}`},
	} {
		t.Run(tc.body, func(t *testing.T) {
			calls := 0
			app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				if _, err := io.WriteString(w, tc.body); err != nil {
					t.Error(err)
				}
			}))
			w := facadeRequest(app, "POST", "/api/v2/challenges/"+scopedOrg+"/verify", `{"commandID":"retained","challengeID":"`+scopedOrg+`","code":"123456"}`)
			if w.Code != tc.status || calls != 1 {
				t.Fatalf("owner error status=%d want=%d calls=%d", w.Code, tc.status, calls)
			}
		})
	}
}

func TestAuthFacadeRejectsForeignVerifiedChallenge(t *testing.T) {
	app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"challenge":{"challengeID":"`+scopedRestaurant+`","expiresAt":"2099-10-13T10:00:00+03:00","resendAvailableAt":"2099-10-13T09:00:00+03:00","state":"verified"},"proof":"foreign-proof","retainUntil":"2099-10-13T10:00:00+03:00"}`); err != nil {
			t.Error(err)
		}
	}))
	w := facadeRequest(app, "POST", "/api/v2/challenges/"+scopedOrg+"/verify", `{"commandID":"retained","challengeID":"`+scopedOrg+`","code":"123456"}`)
	if w.Code != 503 || strings.Contains(w.Body.String(), "foreign-proof") || !strings.Contains(w.Body.String(), `"outcome":"unknown"`) {
		t.Fatalf("foreign challenge accepted: status=%d", w.Code)
	}
}

func TestAuthFacadeUnknownDoesNotReplayMutation(t *testing.T) {
	calls := 0
	const body = `{ "commandID": "retained/α", "name": "Exact payload" }`
	app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		actual, err := io.ReadAll(r.Body)
		if err != nil || string(actual) != body {
			t.Error("uncertain mutation input changed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		if _, err := io.WriteString(w, `{"incomplete":`); err != nil {
			t.Error(err)
		}
	}))
	w := facadeRequest(app, "POST", "/api/v2/orgs/"+scopedOrg+"/restaurants", body)
	if w.Code != 503 || calls != 1 || len(w.Header().Values("Set-Cookie")) != 0 || !strings.Contains(w.Body.String(), `"outcome":"unknown"`) {
		t.Fatalf("unknown mutation status=%d Auth calls=%d", w.Code, calls)
	}
}

func TestAuthFacadeRejectsForeignRestaurantDeletion(t *testing.T) {
	app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		if _, err := io.WriteString(w, `{"operationID":"44444444-4444-4444-8444-444444444444","commandID":"retained","orgID":"`+scopedOrg+`","restaurantIDs":["`+scopedOtherRestaurant+`"],"lifecycle":"deleting","lifecycleVersion":"2","cleanup":"pending","services":[]}`); err != nil {
			t.Error(err)
		}
	}))
	w := facadeRequest(app, "DELETE", "/api/v2/orgs/"+scopedOrg+"/restaurants/"+scopedRestaurant, `{"commandID":"retained"}`)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"outcome":"unknown"`) || strings.Contains(w.Body.String(), scopedOtherRestaurant) {
		t.Fatalf("foreign restaurant deletion accepted: status=%d", w.Code)
	}
}
