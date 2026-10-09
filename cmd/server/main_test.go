package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyRoutesPreserveRequestAndResponse(t *testing.T) {
	for _, service := range []string{"serving", "warehouse"} {
		t.Run(service, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/orders" || r.URL.RawQuery != "limit=2" || r.Method != http.MethodPost {
					t.Errorf("request: %s %s", r.Method, r.URL)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != "payload" {
					t.Errorf("body: %s", body)
				}
				w.Header().Set("X-Upstream", service)
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte("accepted"))
			}))
			defer upstream.Close()
			t.Setenv(strings.ToUpper(service)+"_URL", upstream.URL)
			app, err := handler()
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/"+service+"/orders?limit=2", strings.NewReader("payload")))
			if response.Code != http.StatusAccepted || response.Header().Get("X-Upstream") != service || response.Body.String() != "accepted" {
				t.Fatalf("response: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestInvalidUpstreamRejected(t *testing.T) {
	t.Setenv("SERVING_URL", "file:///tmp/upstream")
	if _, err := handler(); err == nil {
		t.Fatal("invalid upstream accepted")
	}
}
