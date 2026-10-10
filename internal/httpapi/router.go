// Package httpapi exposes gateway routes over injected upstream handlers.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Upstreams are the handlers that receive requests without their /api/<service> prefix.
type Upstreams struct {
	Serving   http.Handler
	Warehouse http.Handler
}

func NewRouter(upstreams Upstreams) (http.Handler, error) {
	if upstreams.Serving == nil || upstreams.Warehouse == nil {
		return nil, errors.New("router requires serving and warehouse upstreams")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "umir-gateway"})
	})
	mux.Handle("/api/serving/", http.StripPrefix("/api/serving", upstreams.Serving))
	mux.Handle("/api/warehouse/", http.StripPrefix("/api/warehouse", upstreams.Warehouse))
	return mux, nil
}
