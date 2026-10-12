package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteProblemCarriesRequestID(t *testing.T) {
	handler := WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteProblem(w, r, http.StatusForbidden, Problem{Code: "InvalidOrigin", Message: "request origin is not allowed"})
	}), func() string { return "req-1" })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/serving/orders", nil))
	if response.Code != http.StatusForbidden || response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response: %d %v", response.Code, response.Header())
	}
	want := `{"code":"InvalidOrigin","message":"request origin is not allowed","requestID":"req-1"}` + "\n"
	if got := response.Body.String(); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

func TestWriteProblemFieldErrors(t *testing.T) {
	response := httptest.NewRecorder()
	WriteProblem(response, httptest.NewRequest(http.MethodPatch, "/", nil), http.StatusUnprocessableEntity,
		Problem{Code: "InvalidDisplayName", Message: "rejected", FieldErrors: map[string]string{"displayName": "TooShort"}})
	want := `{"code":"InvalidDisplayName","message":"rejected","fieldErrors":{"displayName":"TooShort"},"requestID":""}` + "\n"
	if got := response.Body.String(); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

func TestEachRequestGetsItsOwnID(t *testing.T) {
	var seen []string
	issued := 0
	handler := WithRequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = append(seen, RequestID(r))
	}), func() string { issued++; return fmt.Sprintf("req-%d", issued) })
	for range 2 {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if len(seen) != 2 || seen[0] != "req-1" || seen[1] != "req-2" {
		t.Fatalf("ids = %v", seen)
	}
	if got := RequestID(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Errorf("outside the middleware: %q", got)
	}
}
