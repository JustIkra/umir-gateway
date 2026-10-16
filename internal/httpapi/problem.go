package httpapi

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

// Problem is the gateway's own JSON error for account routes, guard rejections and malformed
// requests. Code and the FieldErrors codes are stable; Message is for logs and developers, the client
// picks its own text by code.
type Problem struct {
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	FieldErrors map[string]string `json:"fieldErrors,omitempty"`
	RequestID   string            `json:"requestID"`
	// SessionRevoked is set only on PasswordChangeRateLimited: whether this response revoked the session.
	SessionRevoked *bool `json:"sessionRevoked,omitempty"`
}

type requestIDKey struct{}

// WithRequestID gives every request a fresh ID, ignoring any the client sent, and returns it in the
// X-Request-ID header of the response, errors included. Error bodies and log lines carry it too.
func WithRequestID(next http.Handler, newID func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newID()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// RequestIDFromContext returns the request ID of ctx, or "" for work that has none, such as the
// background scheduler.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// RequestID returns the ID set by WithRequestID, or "" outside it.
func RequestID(r *http.Request) string { return RequestIDFromContext(r.Context()) }

// WriteProblem answers with p and the request's ID. The response is never cached.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, p Problem) {
	p.RequestID = RequestID(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		log.Printf("problem response %s: %v", p.RequestID, err)
	}
}
