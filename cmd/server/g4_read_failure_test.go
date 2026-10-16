package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/authclient"
	"github.com/JustIkra/umir-gateway/internal/adapters/httpupstream"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/journal"
	"github.com/JustIkra/umir-gateway/internal/live"
)

func TestG4CommittedPreparationInterruptedBody(t *testing.T) {
	for _, path := range []string{
		"/api/v2/r/" + scopedRestaurant + "/warehouse/inventory",
		"/api/v2/orgs/" + scopedOrg + "/analytics/summary?restaurantID=" + scopedRestaurant + "&expectedSettingsVersion=2",
	} {
		for _, failure := range []string{"complete-control", "truncated", "oversized", "close-failed"} {
			label := path + "/" + failure
			t.Run(label, func(t *testing.T) {
				f := newScopedFixture(t, failure == "close-failed")
				f.peer = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Umir-Invalidation-Required", "true")
					w.Header().Set("X-Umir-Committed-Version", "4")
					w.Header().Set("X-Umir-Runtime-Epoch", scopedEpoch)
					if failure == "truncated" {
						w.Header().Set("Content-Length", "1000")
					}
					w.WriteHeader(503)
					switch failure {
					case "truncated":
						if _, err := io.WriteString(w, `{"code":`); err != nil {
							t.Error(err)
						}
					case "oversized":
						if _, err := io.WriteString(w, strings.Repeat("x", (8<<20)+1)); err != nil {
							return
						}
					default:
						writeScopedJSON(t, w, map[string]any{"code": "UpstreamUnavailable", "outcome": "unavailable", "message": "committed preparation", "retryable": false})
					}
				}
				server := httptest.NewServer(f.handler)
				defer server.Close()
				response := g4Open(t, server, scopedRestaurant, "", "session")
				defer func() {
					if err := response.Body.Close(); err != nil {
						t.Error(err)
					}
				}()
				reader := bufio.NewReader(response.Body)
				g4Frame(t, reader)
				neighbor := g4Open(t, server, scopedOtherRestaurant, "", "session")
				defer func() {
					if err := neighbor.Body.Close(); err != nil {
						t.Error(err)
					}
				}()
				neighborReader := bufio.NewReader(neighbor.Body)
				g4Frame(t, neighborReader)
				neighborFrame := make(chan string, 1)
				go func() {
					for {
						line, err := neighborReader.ReadString('\n')
						if err != nil {
							neighborFrame <- "closed"
							return
						}
						if strings.HasPrefix(line, "event:") {
							neighborFrame <- line
							return
						}
					}
				}()
				result := f.request("GET", path, "", nil)
				t.Logf("public result: %d %s", result.Code, result.Body.String())
				if strings.Contains(path, "/summary") {
					if result.Code != 200 || !strings.Contains(result.Body.String(), `"status":"unavailable"`) || !strings.Contains(result.Body.String(), `"outcome":"unavailable"`) || strings.Contains(result.Body.String(), `"stock":`) {
						t.Errorf("summary invented success: %s", result.Body.String())
					}
				} else if result.Code < 500 || !strings.Contains(result.Body.String(), `"outcome":"unavailable"`) {
					t.Errorf("read invented success: %d %s", result.Code, result.Body.String())
				}
				if result.Header().Get("X-Umir-Invalidation-Required") != "" {
					t.Error("private metadata reached browser")
				}
				f.mu.Lock()
				requestCount := len(f.requests)
				f.mu.Unlock()
				if requestCount != 1 {
					t.Errorf("repeated interrupted read: %d", requestCount)
				}
				next := make(chan string, 1)
				go func() {
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							next <- "closed"
							return
						}
						if strings.HasPrefix(line, "event:") {
							next <- line
							return
						}
					}
				}()
				select {
				case line := <-next:
					if line != "event: change\n" {
						t.Errorf("committed preparation notification = %q", line)
					}
				case <-time.After(500 * time.Millisecond):
					t.Error("missing restaurant invalidation after committed preparation metadata")
				}
				select {
				case event := <-neighborFrame:
					t.Errorf("neighbor changed: %q", event)
				case <-time.After(50 * time.Millisecond):
				}
			})
		}
	}
}

type g4CloseFailureTransport struct{ base http.RoundTripper }

func (tr g4CloseFailureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := tr.base.RoundTrip(r)
	if err == nil && response != nil && response.Body != nil {
		response.Body = g4CloseFailureBody{response.Body}
	}
	return response, err
}

type g4CloseFailureBody struct{ io.ReadCloser }

func (b g4CloseFailureBody) Close() error {
	return errors.Join(b.ReadCloser.Close(), errors.New("synthetic response close failure"))
}
func g4CloseFailureHandler(t *testing.T, cfg config.Config) http.Handler {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	auth, err := authclient.New(authclient.Options{URL: cfg.AuthURL, ServiceKey: cfg.AuthServiceKey, Timeout: cfg.AuthTimeout, Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	business, err := httpupstream.NewScopedClient(map[string]httpupstream.ScopedTarget{
		"warehouse": {URL: cfg.WarehouseURL, ServiceKey: cfg.WarehouseServiceKey},
		"serving":   {URL: cfg.ServingURL, ServiceKey: cfg.ServingServiceKey},
		"feedback":  {URL: cfg.FeedbackURL, ServiceKey: cfg.FeedbackServiceKey},
	}, g4CloseFailureTransport{http.DefaultTransport}, cfg.UpstreamTimeout)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := journal.NewScoped(scopedEpoch, 100, 100, 100, time.Now, rand.Text, nil)
	if err != nil {
		t.Fatal(err)
	}
	streams, err := live.NewHandler(live.ScopedOptions{Auth: auth, Journal: changes, Clock: live.SystemClock{}, PerSession: 4, PerOrg: 4, Total: 4, WriteTimeout: time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(streams.Close)
	handler, err := httpapi.NewScoped(httpapi.ScopedOptions{Live: streams, Changes: changes, Auth: auth, Business: business, Origin: cfg.Operator.PublicOrigin, Now: time.Now, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
