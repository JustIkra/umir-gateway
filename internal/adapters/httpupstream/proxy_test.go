package httpupstream

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// recordingTransport keeps the outbound request and answers with a fixed response.
type recordingTransport struct {
	request  *http.Request
	body     string
	response *http.Response
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.request = r
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	t.body = string(body)
	return t.response, nil
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}, "X-Upstream": {"serving"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNewProxyRejectsInvalidDependencies(t *testing.T) {
	transport := &recordingTransport{}
	for name, tc := range map[string]struct {
		target    string
		transport http.RoundTripper
	}{
		"nil target":      {"", transport},
		"nil transport":   {"http://serving:8080", nil},
		"non-http scheme": {"file:///tmp/upstream", transport},
		"missing host":    {"http://", transport},
		"credentials":     {"http://user:secret@serving:8080", transport},
		"query":           {"http://serving:8080?debug=1", transport},
	} {
		t.Run(name, func(t *testing.T) {
			var target *url.URL
			if tc.target != "" {
				target = mustURL(t, tc.target)
			}
			if _, err := NewProxy(target, tc.transport); err == nil {
				t.Fatal("invalid dependency accepted")
			}
		})
	}
}

func TestProxyForwardsRequestUnchanged(t *testing.T) {
	transport := &recordingTransport{response: jsonResponse(http.StatusOK, `{}`)}
	proxy, err := NewProxy(mustURL(t, "http://serving:8080/base"), transport)
	if err != nil {
		t.Fatal(err)
	}
	const rawQuery = "dishID=%D0%BF%D0%B0%D1%81%D1%82%D0%B0%2B1&cutoffAt=2026-10-10T12:00:00%2B03:00&note=a+b"
	const body = `{"commandID":"c-1","quantity":"9007199254740993","lineNo":"9007199254740993"}`
	request := httptest.NewRequest(http.MethodPost, "/items/%D0%B0%2Fb?"+rawQuery, strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:51000"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Client-Note", "kept")
	request.Header.Set("X-Forwarded-For", "203.0.113.66")
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "dropped")

	proxy.ServeHTTP(httptest.NewRecorder(), request)

	out := transport.request
	if out == nil {
		t.Fatal("upstream was not called")
	}
	if out.Method != http.MethodPost || out.URL.Host != "serving:8080" {
		t.Errorf("target: %s %s", out.Method, out.URL)
	}
	if got := out.URL.EscapedPath(); got != "/base/items/%D0%B0%2Fb" {
		t.Errorf("path: %s", got)
	}
	if out.URL.RawQuery != rawQuery {
		t.Errorf("query:\n got %s\nwant %s", out.URL.RawQuery, rawQuery)
	}
	if transport.body != body {
		t.Errorf("body: %s", transport.body)
	}
	if out.Header.Get("Content-Type") != "application/json" || out.Header.Get("X-Client-Note") != "kept" {
		t.Errorf("end-to-end headers: %v", out.Header)
	}
	if out.Header.Get("X-Hop") != "" {
		t.Errorf("hop-by-hop header forwarded: %v", out.Header)
	}
	if got := out.Header.Get("X-Forwarded-For"); got != "192.0.2.10" {
		t.Errorf("client-supplied X-Forwarded-For kept: %q", got)
	}
}

func TestProxyReturnsUpstreamResponseUnchanged(t *testing.T) {
	const body = `{"kind":"ProposalSuperseded","supersededBy":"p-2","stateVersion":"9007199254740993"}`
	for _, status := range []int{http.StatusAccepted, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			proxy, err := NewProxy(mustURL(t, "http://serving:8080"), &recordingTransport{response: jsonResponse(status, body)})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/order-confirmations", strings.NewReader(`{}`)))
			if response.Code != status || response.Body.String() != body ||
				response.Header().Get("X-Upstream") != "serving" || response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("response: %d %v %s", response.Code, response.Header(), response.Body)
			}
		})
	}
}
