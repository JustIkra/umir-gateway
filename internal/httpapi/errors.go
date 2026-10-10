package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
)

// WriteTransportError answers when no upstream response was received.
// A write request may still have been recorded upstream, so its outcome is unknown.
func WriteTransportError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := http.StatusBadGateway, "UpstreamUnavailable", "upstream service did not respond"
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		status, code, message = http.StatusGatewayTimeout, "UpstreamTimeout", "upstream service did not respond in time"
	}
	outcome := "unknown"
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		outcome = "unavailable"
	}
	log.Printf("upstream %s %s: %s: %v", r.Method, r.URL.Path, code, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message, "outcome": outcome})
}
