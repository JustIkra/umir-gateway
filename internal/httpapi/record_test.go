package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestRouterRecordsAdmittedWritesOnly(t *testing.T) {
	routes, router := newTestRouter(t)
	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/api/warehouse/receipts?draft=1"},
		{http.MethodPut, "/api/serving/menu/items/d1"},
		{http.MethodPatch, "/api/serving/stop-list"},
		{http.MethodDelete, "/api/warehouse/items/%D0%B0"},
		{http.MethodPost, "/api/serving/healthz"},
		{http.MethodGet, "/api/serving/menu"},
		{http.MethodHead, "/api/warehouse/healthz"},
		{http.MethodOptions, "/api/serving/menu"},
		{http.MethodPatch, "/api/operator/me/display-name"},
		{http.MethodGet, "/api/operator/me"},
		{http.MethodPost, "/api/operator/session"},
		{http.MethodDelete, "/api/operator/session"},
		{http.MethodPatch, "/api/operator/me/password"},
		{http.MethodPost, "/api/operator/me/display-name"},
		{http.MethodPost, "/api/feedback"},
	} {
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.target, nil))
	}
	want := []string{
		"POST /api/warehouse/receipts 418",
		"PUT /api/serving/menu/items/d1 418",
		"PATCH /api/serving/stop-list 418",
		"DELETE /api/warehouse/items/а 418",
		"POST /api/serving/healthz 418",
		"PATCH /api/operator/me/display-name 418",
	}
	if !slices.Equal(routes.recorded, want) {
		t.Fatalf("recorded %q, want %q", routes.recorded, want)
	}
}

// recordThrough sends one POST through record to upstream and returns the reported status.
func recordThrough(t *testing.T, upstream http.HandlerFunc) (int, *httptest.ResponseRecorder) {
	t.Helper()
	var reported []int
	h := record(upstream, func(_, _ string, status int) { reported = append(reported, status) })
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/serving/order-confirmations", nil))
	if len(reported) != 1 {
		t.Fatalf("reported %v", reported)
	}
	return reported[0], w
}

func TestRecordReportsTheFinalStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream http.HandlerFunc
		want     int
	}{
		{"201", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }, http.StatusCreated},
		{"200 by body", func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.WriteString(w, "{}"); err != nil {
				t.Error(err)
			}
		}, http.StatusOK},
		{"103 then 202", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusAccepted)
		}, http.StatusAccepted},
		{"nothing written", func(http.ResponseWriter, *http.Request) {}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if status, _ := recordThrough(t, tc.upstream); status != tc.want {
				t.Fatalf("reported %d, want %d", status, tc.want)
			}
		})
	}
}

func TestRecordReportsZeroWithoutAnUpstreamResponse(t *testing.T) {
	status, w := recordThrough(t, func(w http.ResponseWriter, r *http.Request) {
		WriteTransportError(w, r, errors.New("connection reset"))
	})
	if status != 0 || w.Code != http.StatusBadGateway {
		t.Fatalf("reported %d for a %d transport error", status, w.Code)
	}
}

func TestRecordReportsWhenTheProxyAborts(t *testing.T) {
	var reported []int
	h := record(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic(http.ErrAbortHandler) // what ReverseProxy does when the upstream body breaks
	}), func(_, _ string, status int) { reported = append(reported, status) })
	func() {
		defer func() {
			recovered := recover()
			if err, ok := recovered.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
				t.Errorf("panic = %v", recovered)
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/serving/orders", nil))
	}()
	if !slices.Equal(reported, []int{http.StatusOK}) {
		t.Fatalf("reported %v", reported)
	}
}

// deadlineRecorder accepts write deadlines, as a server connection does.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestRecordKeepsResponseControl(t *testing.T) {
	want := time.Date(2026, 10, 12, 14, 0, 0, 0, time.UTC)
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	h := record(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(want); err != nil {
			t.Errorf("SetWriteDeadline: %v", err)
		}
	}), func(string, string, int) {})
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/serving/orders", nil))
	if !w.deadline.Equal(want) {
		t.Fatalf("deadline = %v", w.deadline)
	}
}

func TestRouterHidesExpirationRunsFromTheBrowser(t *testing.T) {
	for _, target := range []string{
		"/api/warehouse/expiration-runs",
		"/api/warehouse/expiration-runs?force=1",
		"/api/warehouse/expiration-runs/",
		"/api/warehouse/expiration-runs/123",
		"/api/warehouse/expiration%2Druns",
		"/api/warehouse/expiration-runs%2Fx",
	} {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			t.Run(fmt.Sprintf("%s %s", method, target), func(t *testing.T) {
				routes, router := newTestRouter(t)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, httptest.NewRequest(method, target, nil))
				var body Problem
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusNotFound || body.Code != "NotFound" {
					t.Fatalf("%d %s", response.Code, response.Body)
				}
				if routes.warehouse.request != nil || len(routes.guarded) != 0 || len(routes.recorded) != 0 {
					t.Fatalf("reached warehouse %v, guard %v, journal %v", routes.warehouse.request != nil, routes.guarded, routes.recorded)
				}
			})
		}
	}
}
