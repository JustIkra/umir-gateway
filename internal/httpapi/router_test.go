package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recordingHandler remembers the request it received after routing.
type recordingHandler struct{ request *http.Request }

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.request = r
	w.WriteHeader(http.StatusTeapot)
}

func TestNewRouterRejectsMissingUpstream(t *testing.T) {
	for name, upstreams := range map[string]Upstreams{
		"serving":   {Warehouse: &recordingHandler{}},
		"warehouse": {Serving: &recordingHandler{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRouter(upstreams); err == nil {
				t.Fatal("missing upstream accepted")
			}
		})
	}
}

func TestRouterSendsPrefixToItsUpstreamWithoutPrefix(t *testing.T) {
	for _, tc := range []struct {
		target, wantService, wantPath, wantQuery string
	}{
		{"/api/serving/menu?view=full", "serving", "/menu", "view=full"},
		{"/api/serving/healthz", "serving", "/healthz", ""},
		{"/api/serving/items/%D0%B0%2Fb", "serving", "/items/%D0%B0%2Fb", ""},
		{"/api/warehouse/expiring-batches?cutoffAt=2026-10-10T12:00:00%2B03:00", "warehouse", "/expiring-batches", "cutoffAt=2026-10-10T12:00:00%2B03:00"},
		{"/api/warehouse/healthz", "warehouse", "/healthz", ""},
	} {
		t.Run(tc.target, func(t *testing.T) {
			serving, warehouse := &recordingHandler{}, &recordingHandler{}
			router, err := NewRouter(Upstreams{Serving: serving, Warehouse: warehouse})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.target, nil))

			chosen, other := serving, warehouse
			if tc.wantService == "warehouse" {
				chosen, other = warehouse, serving
			}
			if other.request != nil {
				t.Fatalf("request reached the other upstream: %s", other.request.URL)
			}
			if chosen.request == nil {
				t.Fatalf("request did not reach %s: %d", tc.wantService, response.Code)
			}
			if got := chosen.request.URL.EscapedPath(); got != tc.wantPath {
				t.Errorf("path: %s", got)
			}
			if chosen.request.URL.RawQuery != tc.wantQuery {
				t.Errorf("query: %s", chosen.request.URL.RawQuery)
			}
			if response.Code != http.StatusTeapot {
				t.Errorf("upstream status replaced: %d", response.Code)
			}
		})
	}
}

func TestRouterServesOwnHealth(t *testing.T) {
	serving, warehouse := &recordingHandler{}, &recordingHandler{}
	router, err := NewRouter(Upstreams{Serving: serving, Warehouse: warehouse})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" ||
		body["status"] != "ok" || body["service"] != "umir-gateway" || len(body) != 2 {
		t.Fatalf("health: %d %v %v", response.Code, response.Header(), body)
	}
	if serving.request != nil || warehouse.request != nil {
		t.Fatal("gateway health reached an upstream")
	}
}

func TestRouterRejectsUnknownPath(t *testing.T) {
	serving, warehouse := &recordingHandler{}, &recordingHandler{}
	router, err := NewRouter(Upstreams{Serving: serving, Warehouse: warehouse})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/kitchen/menu", nil))
	if response.Code != http.StatusNotFound || serving.request != nil || warehouse.request != nil {
		t.Fatalf("unknown path: %d", response.Code)
	}
}
