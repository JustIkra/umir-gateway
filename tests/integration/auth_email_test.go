package integration_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuthUserEmailSchemaBeforeSuccess(t *testing.T) {
	for _, email := range []struct {
		name, value string
		valid       bool
	}{
		{"absent", "", true},
		{"address", "operator@example.test", true},
		{"tag and uppercase", "Operator+tag@EXAMPLE.TEST", true},
		{"maximum length", strings.Repeat("a", 241) + "@example.test", true},
		{"missing at", "not-an-email", false},
		{"over maximum", strings.Repeat("a", 242) + "@example.test", false},
		{"review counterexample", strings.Repeat("a", 250) + "@example.test", false},
		{"empty", "", false},
		{"consecutive local dots", "a..b@example.test", false},
		{"leading local dot", ".operator@example.test", false},
		{"display address", "Operator <operator@example.test>", false},
		{"single label domain", "operator@example", false},
		{"invalid domain", "operator@-example.test", false},
		{"newline", "operator@example.test\n", false},
		{"non ASCII", "operat\u017for@example.test", false},
	} {
		for _, prefix := range []string{"/api/v2", "/api/operator"} {
			for _, operation := range []struct {
				name, method, path, body string
			}{
				{"login", http.MethodPost, "/session", `{"login":"operator","password":"password-secret"}`},
				{"me", http.MethodGet, "/me", ""},
				{"profile", http.MethodPatch, "/me/display-name", `{"displayName":"Changed"}`},
			} {
				t.Run(email.name+prefix+"/"+operation.name, func(t *testing.T) {
					encoded, err := json.Marshal(email.value)
					if err != nil {
						t.Fatal(err)
					}
					view := authView
					if email.name != "absent" {
						view = strings.Replace(view, `"credentialVersion":"1"`, `"credentialVersion":"1","email":`+string(encoded), 1)
					}
					var fields map[string]json.RawMessage
					if err := json.Unmarshal([]byte(view), &fields); err != nil {
						t.Fatal(err)
					}
					upstream := view
					cookies := 0
					switch operation.name {
					case "login":
						upstream = `{"view":` + view + `,"sessionToken":"email-session"}`
						cookies = 1
					case "profile":
						upstream = string(fields["user"])
					}
					var calls atomic.Int32
					api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						calls.Add(1)
						reply(t, w, upstream)
					}))
					body := operation.body
					if prefix == "/api/v2" && body != "" {
						body = strings.TrimSuffix(body, "}") + `,"commandID":"email-schema"}`
					}
					w := callAuth(api, operation.method, prefix+operation.path, body, nil)
					t.Logf("emailBytes=%d status=%d cookies=%d body=%s", len(email.value), w.Code, len(w.Header().Values("Set-Cookie")), w.Body.String())
					if calls.Load() != 1 {
						t.Fatalf("Auth exchanges=%d, want one without replay", calls.Load())
					}
					if email.valid {
						if w.Code != http.StatusOK || len(w.Header().Values("Set-Cookie")) != cookies {
							t.Fatalf("valid User.email refused: %d %s %v", w.Code, w.Body, w.Header())
						}
						if prefix == "/api/v2" && email.name != "absent" && !strings.Contains(w.Body.String(), `"email":`+string(encoded)) {
							t.Fatal("valid email was changed or omitted")
						}
						return
					}
					if w.Code != http.StatusServiceUnavailable || len(w.Header().Values("Set-Cookie")) != 0 {
						t.Fatalf("schema-invalid User.email accepted: %d %s %v", w.Code, w.Body, w.Header())
					}
					if prefix == "/api/v2" {
						outcome := "unknown"
						if operation.name == "me" {
							outcome = "unavailable"
						}
						if !strings.Contains(w.Body.String(), `"outcome":"`+outcome+`"`) {
							t.Fatalf("malformed result outcome changed: %s", w.Body)
						}
					} else if operation.name != "me" {
						code := "SessionUpdateOutcomeUnknown"
						if operation.name == "profile" {
							code = "AccountUpdateOutcomeUnknown"
						}
						if !strings.Contains(w.Body.String(), code) {
							t.Fatalf("alias lost unknown outcome: %s", w.Body)
						}
					}
				})
			}
		}
	}
}
