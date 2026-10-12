package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/journal"
)

// openLive opens /api/live with client; the stream closes when the test ends.
func openLive(t *testing.T, client *http.Client, address string) *bufio.Reader {
	t.Helper()
	response, err := client.Get(address + "/api/live")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close stream: %v", err)
		}
	})
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream; charset=utf-8" {
		t.Fatalf("stream: %d %v", response.StatusCode, response.Header)
	}
	return bufio.NewReader(response.Body)
}

// nextEvent returns the next event, skipping the retry field and pings.
func nextEvent(t *testing.T, reader *bufio.Reader) (name, data string) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read stream: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "" && name != "":
			return name, data
		}
	}
}

// greeting reads the four events every stream starts with and checks their order.
func greeting(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	var names []string
	for range 4 {
		name, _ := nextEvent(t, reader)
		names = append(names, name)
	}
	if want := []string{"change", "tick", "session", "upstream"}; !slices.Equal(names, want) {
		t.Fatalf("first events %v, want %v", names, want)
	}
}

// liveGateway serves a gateway whose upstreams answer 200 and signs in over HTTP.
func liveGateway(t *testing.T, timeout string) (components, map[string]string, string, *http.Client) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(upstream.Close)
	values := operatorEnv(t)
	values["SERVING_URL"], values["WAREHOUSE_URL"], values["UPSTREAM_TIMEOUT"] = upstream.URL, upstream.URL, timeout
	app := assemble(t, values)
	front := httptest.NewServer(app.handler)
	t.Cleanup(front.Close) // registered first, so it runs after the streams are closed
	return app, values, front.URL, signInOver(t, front.URL)
}

func TestLiveStreamOutlivesTheUpstreamTimeout(t *testing.T) {
	app, _, address, client := liveGateway(t, "100ms")
	reader := openLive(t, client, address)
	greeting(t, reader)
	time.Sleep(300 * time.Millisecond)
	app.journal.Append(journal.Entry{Source: journal.SourceRequest, Outcome: journal.OutcomeSuccess})
	name, data := nextEvent(t, reader)
	var change struct{ Epoch, Seq string }
	if err := json.Unmarshal([]byte(data), &change); err != nil || name != "change" || change.Seq != "1" || change.Epoch == "" {
		t.Fatalf("after the upstream timeout: %s %s", name, data)
	}
}

// send makes one request with the operator's cookies and returns its status.
func send(t *testing.T, client *http.Client, method, target string, header map[string]string) int {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range header {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func TestStreamAndBackgroundReadsLeaveTheAccountFileAlone(t *testing.T) {
	_, values, address, client := liveGateway(t, "")
	stored := func() []byte {
		data, err := os.ReadFile(values["OPERATOR_STORE_PATH"])
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := stored()
	greeting(t, openLive(t, client, address))
	background := map[string]string{"X-Umir-Activity": "background"}
	for _, target := range []string{"/api/warehouse/stock", "/api/operator/me"} {
		if status := send(t, client, http.MethodGet, address+target, background); status != http.StatusOK {
			t.Fatalf("background %s: %d", target, status)
		}
	}
	if !bytes.Equal(stored(), before) {
		t.Fatal("the stream or a background read wrote the account file")
	}
	if status := send(t, client, http.MethodGet, address+"/api/warehouse/stock", nil); status != http.StatusOK {
		t.Fatalf("ordinary GET: %d", status)
	}
	if bytes.Equal(stored(), before) {
		t.Fatal("an ordinary GET did not store the renewed deadline")
	}
}

func TestLiveStreamEndsWhenTheOperatorSignsOut(t *testing.T) {
	_, _, address, client := liveGateway(t, "")
	reader := openLive(t, client, address)
	greeting(t, reader)
	response, err := client.Get(address + "/api/operator/csrf")
	if err != nil {
		t.Fatal(err)
	}
	var body struct{ CSRFToken string }
	if err := errors.Join(json.NewDecoder(response.Body).Decode(&body), response.Body.Close()); err != nil {
		t.Fatal(err)
	}
	if status := send(t, client, http.MethodDelete, address+"/api/operator/session",
		map[string]string{"Origin": testOrigin, "X-CSRF-Token": body.CSRFToken}); status != http.StatusNoContent {
		t.Fatalf("logout: %d", status)
	}
	if name, data := nextEvent(t, reader); name != "session-ended" || data != `{"reason":"signed_out"}` {
		t.Fatalf("after logout: %s %s", name, data)
	}
	if rest, err := io.ReadAll(reader); err != nil || len(rest) != 0 {
		t.Fatalf("stream stayed open: %q %v", rest, err)
	}
}

func TestShutdownEndsLiveStreamsAtOnce(t *testing.T) {
	values := operatorEnv(t)
	app := assemble(t, values)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopped := make(chan error, 1)
	go func() { stopped <- run(ctx, newServer(loadConfig(t, values), app), listener, 5*time.Second) }()
	address := "http://" + listener.Addr().String()
	reader := openLive(t, signInOver(t, address), address)
	greeting(t, reader)
	stop()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an open stream held the shutdown")
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("stream did not end cleanly: %v", err)
	}
}
