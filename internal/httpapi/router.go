// Package httpapi exposes gateway routes over injected handlers.
package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// Routes are the handlers behind the gateway's paths. Every field is required: business routes cannot
// be served without Protect.
type Routes struct {
	// Serving and Warehouse receive requests without their /api/<service> prefix.
	Serving   http.Handler
	Warehouse http.Handler
	// Operator serves /api/operator/ with the full path.
	Operator http.Handler
	// Protect admits a business request only for the operator's session.
	Protect func(http.Handler) http.Handler
	// NewRequestID names each request in error responses and logs.
	NewRequestID func() string
}

func NewRouter(routes Routes) (http.Handler, error) {
	if routes.Serving == nil || routes.Warehouse == nil || routes.Operator == nil || routes.Protect == nil || routes.NewRequestID == nil {
		return nil, errors.New("router requires serving, warehouse, operator, protect and request IDs")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", health)
	mux.Handle("/api/operator/", routes.Operator)
	mux.Handle("/api/serving/", business("/api/serving", routes.Serving, routes.Protect))
	mux.Handle("/api/warehouse/", business("/api/warehouse", routes.Warehouse, routes.Protect))
	return WithRequestID(mux, routes.NewRequestID), nil
}

func health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		WriteProblem(w, r, http.StatusMethodNotAllowed, Problem{Code: "MethodNotAllowed", Message: "use GET or HEAD"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "umir-gateway"}); err != nil {
		log.Printf("health response: %v", err)
	}
}

// business leaves only the exact GET/HEAD health check of an upstream public. Every other request
// under prefix passes protect before it can reach the upstream.
func business(prefix string, upstream http.Handler, protect func(http.Handler) http.Handler) http.Handler {
	public := http.StripPrefix(prefix, upstream)
	guarded := protect(public)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == prefix+"/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			public.ServeHTTP(w, r)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}
