package httpapi

import (
	"context"
	"net/http"
)

// exchangeKey carries the *exchange of a recorded request, so WriteTransportError can mark it.
type exchangeKey struct{}

// exchange learns whether the answer came from the gateway because no upstream response arrived.
type exchange struct{ failed bool }

// markTransportFailure tells the recording of r that no upstream response arrived.
func markTransportFailure(r *http.Request) {
	if x, ok := r.Context().Value(exchangeKey{}).(*exchange); ok {
		x.failed = true
	}
}

// record reports the method, path without the query and final status of every request through next:
// 0 when no upstream response arrived or nothing was written. It reports even when next panics, as
// the proxy does when an upstream body breaks after the status was sent.
func record(next http.Handler, report func(method, path string, status int)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x := &exchange{}
		writer := &statusWriter{ResponseWriter: w}
		defer func() {
			status := writer.status
			if x.failed {
				status = 0
			}
			report(r.Method, r.URL.Path, status)
		}()
		next.ServeHTTP(writer, r.WithContext(context.WithValue(r.Context(), exchangeKey{}, x)))
	})
}

// statusWriter remembers the first final status written through it.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 && code >= http.StatusOK {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the deadlines and flushing of the wrapped writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
