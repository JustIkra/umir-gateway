package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/config"
)

type healthTransport struct {
	status int
	err    error
}

func (transport healthTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: transport.status, Body: healthBody{err: transport.err}, Header: make(http.Header)}, nil
}

type healthBody struct {
	err error
}

func (healthBody) Read([]byte) (int, error) { return 0, io.EOF }
func (body healthBody) Close() error        { return body.err }

func TestHealthcheckRetainsCleanupFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			closeErr := errors.New("fixture body close failure")
			original := http.DefaultTransport
			http.DefaultTransport = healthTransport{status: status, err: closeErr}
			t.Cleanup(func() { http.DefaultTransport = original })
			err := healthcheck("8080", "/healthz")
			if !errors.Is(err, closeErr) {
				t.Fatalf("cleanup failure was lost: %v", err)
			}
			if status != http.StatusOK && !strings.Contains(err.Error(), "health status: 503") {
				t.Fatalf("HTTP failure was lost: %v", err)
			}
		})
	}
}

func TestW1HealthcheckProbesReadyzInAuthModeAndHealthzInLegacy(t *testing.T) {
	var paths []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { paths = append(paths, r.URL.Path) }))
	defer peer.Close()
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	legacy := loadConfig(t, map[string]string{"OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin, "OPERATOR_STORE_PATH": "/data/operator/account.json"})
	auth := loadConfig(t, map[string]string{"AUTH_URL": peer.URL, "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "AUTH_SERVICE_KEY": "auth-key", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin})
	for _, cfg := range []config.Config{auth, legacy} {
		if err := healthcheck(target.Port(), healthPath(cfg)); err != nil {
			t.Fatal(err)
		}
	}
	if len(paths) != 2 || paths[0] != "/readyz" || paths[1] != "/healthz" {
		t.Fatalf("probed %v", paths)
	}
}
