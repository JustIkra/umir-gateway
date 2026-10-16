package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/argon2id"
	"github.com/JustIkra/umir-gateway/internal/admission"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/tests/testsupport/memredis"
)

const (
	// testOrigin is the frontend origin the tests configure and send.
	testOrigin   = "http://127.0.0.1:8080"
	testPassword = "correct horse battery staple"
)

var (
	hashOnce  sync.Once
	hashValue string
	hashErr   error
)

// bootstrapHash hashes testPassword once per test binary, at the cheapest cost the gateway accepts.
func bootstrapHash(t *testing.T) string {
	t.Helper()
	hashOnce.Do(func() {
		var hasher *argon2id.Hasher
		if hasher, hashErr = argon2id.New(argon2id.Baseline, rand.Reader); hashErr == nil {
			hashValue, hashErr = hasher.Hash(testPassword)
		}
	})
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	return hashValue
}

// operatorEnv returns the operator settings for one test, with its own 0700 account directory.
func operatorEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "operator")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"OPERATOR_COOKIE_MODE":             "loopback-development",
		"OPERATOR_PUBLIC_ORIGIN":           testOrigin,
		"OPERATOR_STORE_PATH":              filepath.Join(dir, "account.json"),
		"OPERATOR_BOOTSTRAP_LOGIN":         "operator",
		"OPERATOR_BOOTSTRAP_DISPLAY_NAME":  "Оператор",
		"OPERATOR_BOOTSTRAP_PASSWORD_HASH": bootstrapHash(t),
	}
}

// gatewayApp assembles the gateway with a fresh account file and no session.
func gatewayApp(t *testing.T, servingURL, warehouseURL, timeout string) http.Handler {
	t.Helper()
	values := operatorEnv(t)
	values["SERVING_URL"], values["WAREHOUSE_URL"], values["UPSTREAM_TIMEOUT"] = servingURL, warehouseURL, timeout
	return gatewayWith(t, values)
}

// gatewayWith assembles the gateway from settings; two calls with the same settings share the account
// file, like a restarted gateway.
func gatewayWith(t *testing.T, values map[string]string) http.Handler {
	t.Helper()
	return assemble(t, values).handler
}

// assemble builds the gateway's components from settings; the expiration runs are not started.
func assemble(t *testing.T, values map[string]string) components {
	t.Helper()
	cfg := loadConfig(t, values)
	app, err := componentsForTest(t, cfg, log.Default())
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func componentsForTest(t *testing.T, cfg config.Config, logger *log.Logger) (components, error) {
	t.Helper()
	var app components
	var err error
	if cfg.AuthURL != nil {
		app, err = newAuthComponentsWith(cfg, logger, componentEnv{now: time.Now, newTicker: newTicker, admission: testAdmission(t, cfg)})
	} else {
		app, err = newComponents(cfg, logger)
	}
	if err == nil {
		t.Cleanup(func() {
			if app.streams != nil {
				app.streams.Close()
			}
			if app.scopedStreams != nil {
				app.scopedStreams.Close()
			}
			if app.close != nil {
				_ = app.close()
			}
		})
	}
	return app, err
}

func testAdmission(t *testing.T, cfg config.Config) *admission.Service {
	t.Helper()
	store := memredis.New(time.Now())
	budgets := make(map[string]admission.Budget, len(cfg.Budgets))
	for name, budget := range cfg.Budgets {
		budgets[name] = admission.Budget{Limit: budget.Limit, Window: budget.Window, Strict: budget.Strict}
	}
	service, err := admission.New(admission.Options{Limiter: store.Limiter(), Continuity: store.Continuity(), Budgets: budgets, Key: []byte("gateway-test-admission-key-0123456789")})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func loadConfig(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(func(key string) string {
		if key == "AUTH_RUNTIME_SERVICE_KEY" && values[key] == "" && values["AUTH_URL"] != "" {
			return "synthetic-auth-runtime-key"
		}
		return values[key]
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type credentials struct {
	session *http.Cookie
	csrf    string
}

// signIn signs in through app the way the frontend does and returns the session cookie and token.
func signIn(t *testing.T, app http.Handler) credentials {
	t.Helper()
	bootstrap := httptest.NewRecorder()
	app.ServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, "/api/operator/csrf", nil))
	login := httptest.NewRequest(http.MethodPost, "/api/operator/session",
		strings.NewReader(`{"login":"operator","password":"`+testPassword+`"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", testOrigin)
	login.Header.Set("X-CSRF-Token", csrfOf(t, bootstrap))
	login.AddCookie(responseCookie(t, bootstrap, "umir_operator_preauth"))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, login)
	if response.Code != http.StatusOK {
		t.Fatalf("sign in: %d %s", response.Code, response.Body)
	}
	return credentials{session: responseCookie(t, response, "umir_operator_session"), csrf: csrfOf(t, response)}
}

// withSession sends every request as the signed-in operator from the frontend origin.
func withSession(app http.Handler, creds credentials) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		r.AddCookie(creds.session)
		r.Header.Set("X-CSRF-Token", creds.csrf)
		r.Header.Set("Origin", testOrigin)
		app.ServeHTTP(w, r)
	})
}

// csrfOf reads the token of a /csrf response or of a login response.
func csrfOf(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		CSRFToken string `json:"csrfToken"`
		Session   struct {
			CSRFToken string `json:"csrfToken"`
		} `json:"session"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d %q: %v", response.Code, response.Body, err)
	}
	if body.CSRFToken != "" {
		return body.CSRFToken
	}
	if body.Session.CSRFToken == "" {
		t.Fatalf("no CSRF token in %s", response.Body)
	}
	return body.Session.CSRFToken
}

func responseCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, line := range response.Header().Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatal(err)
		}
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("no %s cookie in %v", name, response.Header().Values("Set-Cookie"))
	return nil
}

// signInOver signs in over HTTP; the returned client's jar sends the session cookie.
func signInOver(t *testing.T, address string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Jar: jar}
	response, err := client.Get(address + "/api/operator/csrf")
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap struct {
		CSRFToken string `json:"csrfToken"`
	}
	decodeErr := json.NewDecoder(response.Body).Decode(&bootstrap)
	if err := errors.Join(decodeErr, response.Body.Close()); err != nil || bootstrap.CSRFToken == "" {
		t.Fatalf("csrf bootstrap: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, address+"/api/operator/session",
		strings.NewReader(`{"login":"operator","password":"`+testPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", testOrigin)
	request.Header.Set("X-CSRF-Token", bootstrap.CSRFToken)
	login, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := login.Body.Close(); err != nil || login.StatusCode != http.StatusOK {
		t.Fatalf("sign in: %d %v", login.StatusCode, err)
	}
	return client
}
