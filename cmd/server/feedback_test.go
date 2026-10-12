package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// feedbackPost posts the form from the frontend origin with a fresh anonymous context of app.
func feedbackPost(t *testing.T, app http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	bootstrap := httptest.NewRecorder()
	app.ServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, "/api/operator/csrf", nil))
	request := httptest.NewRequest(http.MethodPost, "/api/feedback?debug=1", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", testOrigin)
	request.Header.Set("X-CSRF-Token", csrfOf(t, bootstrap))
	request.AddCookie(responseCookie(t, bootstrap, "umir_operator_preauth"))
	request.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	return response
}

func TestFeedbackReachesTheServiceWithoutCredentials(t *testing.T) {
	const body = `{"submissionID":"s-1","message":"Спасибо"}`
	var mu sync.Mutex
	var received []*http.Request
	var bodies []string
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		mu.Lock()
		received, bodies = append(received, r), append(bodies, string(data))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "umir_operator_session=forged; Path=/")
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, `{"submissionID":"s-1"}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer service.Close()
	values := operatorEnv(t)
	values["FEEDBACK_URL"] = service.URL
	response := feedbackPost(t, gatewayWith(t, values), body)
	if response.Code != http.StatusCreated || response.Body.String() != `{"submissionID":"s-1"}` ||
		len(response.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("response: %d %v %s", response.Code, response.Header(), response.Body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("service received %d requests", len(received))
	}
	r := received[0]
	if r.Method != http.MethodPost || r.URL.Path != "/feedback" || r.URL.RawQuery != "" || bodies[0] != body {
		t.Errorf("service got %s %s %q", r.Method, r.URL, bodies[0])
	}
	if r.Header.Get("Cookie") != "" || r.Header.Get("X-CSRF-Token") != "" {
		t.Errorf("credentials reached the service: %v", r.Header)
	}
}

func TestFeedbackTimeoutAfterDispatchIsAnUnknownOutcome(t *testing.T) {
	release := make(chan struct{})
	service := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer service.Close()
	defer close(release)
	values := operatorEnv(t)
	values["FEEDBACK_URL"], values["UPSTREAM_TIMEOUT"] = service.URL, (100 * time.Millisecond).String()
	response := feedbackPost(t, gatewayWith(t, values), `{"submissionID":"s-1"}`)
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusGatewayTimeout || body["outcome"] != "unknown" {
		t.Fatalf("response: %d %s", response.Code, response.Body)
	}
}

func TestFeedbackTimeoutKeepsClientConnectionUsable(t *testing.T) {
	var calls atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		if calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer service.Close()
	values := operatorEnv(t)
	values["FEEDBACK_URL"], values["UPSTREAM_TIMEOUT"] = service.URL, (100 * time.Millisecond).String()
	front := httptest.NewServer(gatewayWith(t, values))
	defer front.Close()
	client := front.Client()
	do := func(request *http.Request) *http.Response {
		t.Helper()
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := response.Body.Close(); err != nil {
				t.Errorf("close response body: %v", err)
			}
		})
		return response
	}
	bootstrap, err := http.NewRequest(http.MethodGet, front.URL+"/api/operator/csrf", nil)
	if err != nil {
		t.Fatal(err)
	}
	csrf := do(bootstrap)
	var body struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(csrf.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	// The second post reuses the keep-alive connection of the timed out one.
	for i, want := range []int{http.StatusGatewayTimeout, http.StatusCreated} {
		post, err := http.NewRequest(http.MethodPost, front.URL+"/api/feedback", strings.NewReader(`{"submissionID":"s-1"}`))
		if err != nil {
			t.Fatal(err)
		}
		post.Header.Set("Content-Type", "application/json")
		post.Header.Set("Origin", testOrigin)
		post.Header.Set("X-CSRF-Token", body.CSRFToken)
		for _, cookie := range csrf.Cookies() {
			post.AddCookie(cookie)
		}
		response := do(post)
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Errorf("read response body: %v", err)
		}
		if response.StatusCode != want {
			t.Fatalf("post %d: %d, want %d", i+1, response.StatusCode, want)
		}
	}
}

func TestFeedbackBodyIsReadWithinTheExchangeBudget(t *testing.T) {
	var calls atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer service.Close()
	values := operatorEnv(t)
	values["FEEDBACK_URL"], values["UPSTREAM_TIMEOUT"] = service.URL, (100 * time.Millisecond).String()
	front := httptest.NewServer(gatewayWith(t, values))
	defer front.Close()
	bootstrap, err := front.Client().Get(front.URL + "/api/operator/csrf")
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		CSRFToken string `json:"csrfToken"`
	}
	err = json.NewDecoder(bootstrap.Body).Decode(&body)
	if closeErr := bootstrap.Body.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	// The client sends the rest of the body after the exchange budget has run out.
	reader, writer := io.Pipe()
	go func() {
		_, _ = io.WriteString(writer, `{"submissionID":`)
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(writer, `"s-1"}`)
		_ = writer.Close()
	}()
	post, err := http.NewRequest(http.MethodPost, front.URL+"/api/feedback", reader)
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Origin", testOrigin)
	post.Header.Set("X-CSRF-Token", body.CSRFToken)
	for _, cookie := range bootstrap.Cookies() {
		post.AddCookie(cookie)
	}
	response, err := front.Client().Do(post)
	if err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("slow body: %d, want 400 before dispatch", response.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Error("a body read after the budget reached the service")
	}
}
