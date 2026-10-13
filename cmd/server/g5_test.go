package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestG5AuthModeOwnsScheduler(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer peer.Close()
	app, err := newComponents(loadConfig(t, map[string]string{"AUTH_URL": peer.URL, "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "AUTH_SERVICE_KEY": "auth-key", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if app.expiry == nil {
		t.Fatal("Auth mode has no process-owned due-expiry scheduler")
	}
}
