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

// testRoutes guards with a stub that records what it protected and lets it through.
type testRoutes struct {
	serving, warehouse, operator *recordingHandler
	guarded                      []string
}

func newTestRouter(t *testing.T) (*testRoutes, http.Handler) {
	t.Helper()
	routes := &testRoutes{serving: &recordingHandler{}, warehouse: &recordingHandler{}, operator: &recordingHandler{}}
	router, err := NewRouter(Routes{
		Serving: routes.serving, Warehouse: routes.warehouse, Operator: routes.operator,
		Protect: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				routes.guarded = append(routes.guarded, r.Method+" "+r.URL.Path)
				next.ServeHTTP(w, r)
			})
		},
		NewRequestID: func() string { return "req-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return routes, router
}

func TestNewRouterRequiresEveryRoute(t *testing.T) {
	for name, drop := range map[string]func(*Routes){
		"serving":    func(r *Routes) { r.Serving = nil },
		"warehouse":  func(r *Routes) { r.Warehouse = nil },
		"operator":   func(r *Routes) { r.Operator = nil },
		"protect":    func(r *Routes) { r.Protect = nil },
		"request ID": func(r *Routes) { r.NewRequestID = nil },
	} {
		t.Run(name, func(t *testing.T) {
			routes := Routes{
				Serving: &recordingHandler{}, Warehouse: &recordingHandler{}, Operator: &recordingHandler{},
				Protect: func(next http.Handler) http.Handler { return next }, NewRequestID: func() string { return "" },
			}
			drop(&routes)
			if _, err := NewRouter(routes); err == nil {
				t.Fatal("incomplete routes accepted")
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
			routes, router := newTestRouter(t)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.target, nil))

			chosen, other := routes.serving, routes.warehouse
			if tc.wantService == "warehouse" {
				chosen, other = routes.warehouse, routes.serving
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

func TestRouterGuardsEveryBusinessRouteExceptHealth(t *testing.T) {
	for _, tc := range []struct {
		method, target string
		guarded        bool
	}{
		{http.MethodGet, "/api/serving/menu", true},
		{http.MethodPost, "/api/warehouse/receipts", true},
		{http.MethodOptions, "/api/serving/menu", true},
		{http.MethodGet, "/api/serving/healthz", false},
		{http.MethodHead, "/api/warehouse/healthz", false},
		{http.MethodPost, "/api/serving/healthz", true},
		{http.MethodDelete, "/api/warehouse/healthz", true},
		{http.MethodGet, "/api/serving/healthz/extra", true},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			routes, router := newTestRouter(t)
			router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.target, nil))
			if guarded := len(routes.guarded) == 1; guarded != tc.guarded {
				t.Fatalf("guarded = %v, want %v", routes.guarded, tc.guarded)
			}
		})
	}
}

func TestRouterRejectedRequestNeverReachesUpstream(t *testing.T) {
	serving := &recordingHandler{}
	router, err := NewRouter(Routes{
		Serving: serving, Warehouse: &recordingHandler{}, Operator: &recordingHandler{},
		Protect: func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
		},
		NewRequestID: func() string { return "req-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/serving/menu", nil))
	if response.Code != http.StatusUnauthorized || serving.request != nil {
		t.Fatalf("rejected request: %d, upstream called: %v", response.Code, serving.request != nil)
	}
}

func TestRouterSendsOperatorRoutesUnchanged(t *testing.T) {
	routes, router := newTestRouter(t)
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPatch, "/api/operator/me/display-name", nil))
	if routes.operator.request == nil || routes.operator.request.URL.Path != "/api/operator/me/display-name" ||
		RequestID(routes.operator.request) != "req-1" || len(routes.guarded) != 0 {
		t.Fatalf("operator route: %+v, guarded %v", routes.operator.request, routes.guarded)
	}
}

func TestRouterServesOwnHealth(t *testing.T) {
	routes, router := newTestRouter(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(method, "/healthz", nil))
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s health: %d %v", method, response.Code, response.Header())
		}
		if method == http.MethodHead {
			continue
		}
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["status"] != "ok" || body["service"] != "umir-gateway" || len(body) != 2 {
			t.Fatalf("health: %v", body)
		}
	}
	if routes.serving.request != nil || routes.warehouse.request != nil || len(routes.guarded) != 0 {
		t.Fatal("gateway health reached an upstream or the guard")
	}
}

func TestRouterHealthRejectsOtherMethods(t *testing.T) {
	_, router := newTestRouter(t)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	var body Problem
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d %q: %v", response.Code, response.Body, err)
	}
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" ||
		body.Code != "MethodNotAllowed" || body.RequestID != "req-1" {
		t.Fatalf("POST /healthz: %d %v %+v", response.Code, response.Header(), body)
	}
}

func TestRouterRejectsUnknownPath(t *testing.T) {
	routes, router := newTestRouter(t)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/kitchen/menu", nil))
	if response.Code != http.StatusNotFound || routes.serving.request != nil || routes.warehouse.request != nil {
		t.Fatalf("unknown path: %d", response.Code)
	}
}
