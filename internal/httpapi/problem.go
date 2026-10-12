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
}

type requestIDKey struct{}

// WithRequestID gives every request an ID that its error responses and log lines carry.
func WithRequestID(next http.Handler, newID func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, newID())))
	})
}

// RequestID returns the ID set by WithRequestID, or "" outside it.
func RequestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

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
