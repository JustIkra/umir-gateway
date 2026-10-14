package httpupstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

type g4ResponseTransport struct{ response *http.Response }

func (t g4ResponseTransport) RoundTrip(*http.Request) (*http.Response, error) { return t.response, nil }

type g4ResponseBody struct {
	io.Reader
	readErr, closeErr error
	closed            bool
}

func (b *g4ResponseBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.Reader.Read(p)
}
func (b *g4ResponseBody) Close() error { b.closed = true; return b.closeErr }
func TestG4ResponseConsumptionPreservesMetadataAndCause(t *testing.T) {
	readFailure := errors.New("read failed")
	closeFailure := errors.New("close failed")
	for _, tc := range []struct {
		name, body        string
		readErr, closeErr error
	}{
		{"read", "", readFailure, nil}, {"close", "complete", nil, closeFailure}, {"oversized", strings.Repeat("x", (8<<20)+1), nil, nil}, {"complete", "complete", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &g4ResponseBody{Reader: strings.NewReader(tc.body), readErr: tc.readErr, closeErr: tc.closeErr}
			headers := http.Header{"X-Umir-Invalidation-Required": []string{"true"}, "X-Umir-Committed-Version": []string{"4"}, "X-Umir-Runtime-Epoch": []string{"44444444-4444-4444-8444-444444444444"}}
			origin := &url.URL{Scheme: "http", Host: "synthetic.invalid"}
			targets := map[string]ScopedTarget{}
			for _, service := range []string{"warehouse", "serving", "feedback"} {
				targets[service] = ScopedTarget{origin, "synthetic-key"}
			}
			client, err := NewScopedClient(targets, g4ResponseTransport{&http.Response{StatusCode: 503, Header: headers, Body: body}}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(context.Background(), httpapi.BusinessRequest{Service: "warehouse", Method: http.MethodGet, Path: "/internal/warehouse/v2/r/33333333-3333-4333-8333-333333333333/inventory", Header: make(http.Header)})
			if tc.name == "complete" {
				if err != nil || string(response.Body) != tc.body {
					t.Fatalf("complete response=%+v %v", response, err)
				}
			} else {
				if err == nil || len(response.Body) != 0 {
					t.Fatalf("consumption error returned body or success: %v", err)
				}
				for _, cause := range []error{tc.readErr, tc.closeErr} {
					if cause != nil && !errors.Is(err, cause) {
						t.Errorf("lost cause: %v", err)
					}
				}
			}
			if response.Status != 503 || response.Header.Get("X-Umir-Invalidation-Required") != "true" || response.Header.Get("X-Umir-Committed-Version") != "4" || response.Header.Get("X-Umir-Runtime-Epoch") != headers.Get("X-Umir-Runtime-Epoch") {
				t.Errorf("committed metadata lost: %+v", response)
			}
			headers.Set("X-Umir-Committed-Version", "99")
			if response.Header.Get("X-Umir-Committed-Version") != "4" {
				t.Error("response aliases transport headers")
			}
			if !body.closed {
				t.Error("response not closed")
			}
		})
	}
}
