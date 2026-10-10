package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "net/http: timeout awaiting response headers" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestWriteTransportError(t *testing.T) {
	refused := errors.New("dial tcp serving:8080: connect: connection refused")
	for _, tc := range []struct {
		method      string
		err         error
		wantStatus  int
		wantCode    string
		wantOutcome string
	}{
		{http.MethodPost, refused, http.StatusBadGateway, "UpstreamUnavailable", "unknown"},
		{http.MethodGet, refused, http.StatusBadGateway, "UpstreamUnavailable", "unavailable"},
		{http.MethodHead, refused, http.StatusBadGateway, "UpstreamUnavailable", "unavailable"},
		{http.MethodPost, fmt.Errorf("round trip: %w", context.DeadlineExceeded), http.StatusGatewayTimeout, "UpstreamTimeout", "unknown"},
		{http.MethodGet, timeoutError{}, http.StatusGatewayTimeout, "UpstreamTimeout", "unavailable"},
	} {
		t.Run(tc.method+" "+tc.wantCode, func(t *testing.T) {
			response := httptest.NewRecorder()
			WriteTransportError(response, httptest.NewRequest(tc.method, "/order-confirmations", nil), tc.err)

			if response.Code != tc.wantStatus || response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("response: %d %v", response.Code, response.Header())
			}
			if tc.method == http.MethodHead {
				return
			}
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %q", response.Body)
			}
			if body["code"] != tc.wantCode || body["outcome"] != tc.wantOutcome || body["message"] == "" || len(body) != 3 {
				t.Errorf("body: %v", body)
			}
			if strings.Contains(response.Body.String(), "serving:8080") {
				t.Errorf("internal address exposed: %s", response.Body)
			}
		})
	}
}
