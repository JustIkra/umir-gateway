package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"time"
)

// WriteTransportError answers when no upstream response was received.
// A write request may still have been recorded upstream, so its outcome is unknown.
func WriteTransportError(w http.ResponseWriter, r *http.Request, err error) {
	markTransportFailure(r)
	if deadlineErr := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); deadlineErr != nil && !errors.Is(deadlineErr, http.ErrNotSupported) {
		log.Printf("upstream error write deadline: %v", deadlineErr)
		return
	}
	status, code, message := http.StatusBadGateway, "UpstreamUnavailable", "upstream service did not respond"
	// A spent budget cancels the exchange from several places, so err may be a plain cancellation.
	deadline, budgeted := r.Context().Deadline()
	budgetSpent := budgeted && !time.Now().Before(deadline)
	var netErr net.Error
	if budgetSpent || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
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
	if encodeErr := json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message, "outcome": outcome}); encodeErr != nil {
		log.Printf("upstream error response: %v", encodeErr)
	}
}
