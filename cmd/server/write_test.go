package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func largeUpstream(t *testing.T, size int64) (url string, started, cancelled <-chan struct{}) {
	t.Helper()
	begun, done := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(begun)
		go func() {
			<-r.Context().Done()
			close(done)
		}()
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		if _, err := io.CopyN(w, streamReader{}, size); err != nil {
			t.Logf("upstream stream stopped: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)
	return upstream.URL, begun, done
}

func TestReadingClientReceivesLargeResponse(t *testing.T) {
	const size = 16 << 20
	upstreamURL, _, _ := largeUpstream(t, size)
	front := httptest.NewServer(gateway(t, upstreamURL, unusedUpstream(t), "5s"))
	defer front.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get(front.URL + "/api/serving/large")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Errorf("close response: %v", closeErr)
	}
	if err != nil || response.StatusCode != http.StatusOK || len(body) != size {
		t.Fatalf("response: %d, %d bytes, %v", response.StatusCode, len(body), err)
	}
	if !bytes.Equal(body, bytes.Repeat([]byte{'x'}, size)) {
		t.Fatal("response body differs from the upstream body")
	}
}

func TestGatewayTimeoutPreservesUnknownOutcome(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Consume the body so net/http can detect that the gateway disconnected.
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		<-r.Context().Done()
	}))
	defer upstream.Close()
	front := httptest.NewServer(gateway(t, upstream.URL, unusedUpstream(t), "100ms"))
	defer front.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Post(front.URL+"/api/serving/order-confirmations", "application/json",
		bytes.NewReader([]byte(`{"commandID":"c-1","proposalID":"p-1"}`)))
	if err != nil {
		t.Fatalf("gateway timeout response was lost: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Errorf("close response: %v", closeErr)
	}
	if err != nil || response.StatusCode != http.StatusGatewayTimeout || !bytes.Contains(body, []byte(`"outcome":"unknown"`)) {
		t.Fatalf("response: %d %s %v", response.StatusCode, body, err)
	}
}
