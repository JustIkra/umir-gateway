package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const w1FeedbackBody = `{"submissionID":"77777777-7777-4777-8777-777777777777","name":"A","email":"a@example.test","message":"M","consent":{"accepted":true,"documentVersion":"1"}}`

// w1Anonymous drives POST /api/v2/feedback/anonymous and counts what reaches Auth and Feedback.
type w1Anonymous struct {
	t *testing.T
	f *scopedFixture
}

func newW1Anonymous(t *testing.T, extra map[string]string) *w1Anonymous {
	t.Helper()
	f := newScopedFixtureWith(t, extra)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		writeScopedJSON(t, w, map[string]any{"receipt": map[string]any{"submissionID": "77777777-7777-4777-8777-777777777777", "receivedAt": "2026-10-13T01:00:00+03:00"}, "scope": map[string]any{"kind": "anonymous"}, "state": "accepted"})
	}
	return &w1Anonymous{t, f}
}

type w1Post struct {
	preauth, body, remote, forwarded string
}

func (a *w1Anonymous) post(p w1Post) *httptest.ResponseRecorder {
	a.t.Helper()
	if p.body == "" {
		p.body = w1FeedbackBody
	}
	if p.remote == "" {
		p.remote = "192.0.2.1:1234"
	}
	r := httptest.NewRequest("POST", "/api/v2/feedback/anonymous", strings.NewReader(p.body))
	r.RemoteAddr = p.remote
	if p.forwarded != "" {
		r.Header.Set("X-Forwarded-For", p.forwarded)
	}
	r.AddCookie(&http.Cookie{Name: "umir_operator_preauth", Value: p.preauth})
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("X-CSRF-Token", "csrf")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.f.handler.ServeHTTP(w, r)
	return w
}

func (a *w1Anonymous) reached() (tokens, feedback int) {
	a.f.mu.Lock()
	defer a.f.mu.Unlock()
	return a.f.anonymousTokens, len(a.f.requests)
}

// body i differs only in the message, so each is a new fingerprint.
func w1Body(i int) string {
	return strings.Replace(w1FeedbackBody, `"message":"M"`, fmt.Sprintf(`"message":"M%d"`, i), 1)
}

func TestW1AnonymousFeedbackLimitedPerPreauthBeforeAuthToken(t *testing.T) {
	a := newW1Anonymous(t, nil)
	for i := range 5 {
		if w := a.post(w1Post{preauth: "browser", body: w1Body(i)}); w.Code != 201 {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body)
		}
	}
	tokens, feedback := a.reached()
	w := a.post(w1Post{preauth: "browser", body: w1Body(5)})
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("sixth request: %d %v %s", w.Code, w.Header(), w.Body)
	}
	var failure struct {
		Code, Outcome string
		Details       struct {
			RetryAfterSeconds int `json:"retryAfterSeconds"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &failure); err != nil || failure.Code != "RateLimited" || failure.Outcome != "not_committed" || failure.Details.RetryAfterSeconds < 1 || fmt.Sprint(failure.Details.RetryAfterSeconds) != w.Header().Get("Retry-After") {
		t.Fatalf("refusal body: %s (%v)", w.Body, err)
	}
	if gotTokens, gotFeedback := a.reached(); gotTokens != tokens || gotFeedback != feedback {
		t.Fatalf("a refused request reached Auth or Feedback: tokens %d->%d, feedback %d->%d", tokens, gotTokens, feedback, gotFeedback)
	}
	// Another browser is not affected.
	if w := a.post(w1Post{preauth: "other", body: w1Body(6)}); w.Code != 201 {
		t.Fatalf("another browser: %d", w.Code)
	}
}

func TestW1AnonymousFeedbackRepeatedFingerprintNotCharged(t *testing.T) {
	a := newW1Anonymous(t, nil)
	for i := range 20 {
		if w := a.post(w1Post{preauth: "browser"}); w.Code != 201 {
			t.Fatalf("identical retry %d: %d %s", i, w.Code, w.Body)
		}
	}
	// The retried submission cost one slot of five.
	for i := 1; i < 5; i++ {
		if w := a.post(w1Post{preauth: "browser", body: w1Body(i)}); w.Code != 201 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := a.post(w1Post{preauth: "browser", body: w1Body(9)}); w.Code != 429 {
		t.Fatalf("sixth distinct submission: %d", w.Code)
	}
}

func TestW1AnonymousFeedbackInvalidBodyOutsideBudget(t *testing.T) {
	a := newW1Anonymous(t, nil)
	for i := range 30 {
		if w := a.post(w1Post{preauth: "browser", body: fmt.Sprintf(`{"submissionID":"bad-%d"}`, i)}); w.Code != 400 {
			t.Fatalf("invalid body %d: %d", i, w.Code)
		}
	}
	if w := a.post(w1Post{preauth: "browser"}); w.Code != 201 {
		t.Fatalf("valid request after invalid ones: %d %s", w.Code, w.Body)
	}
}

func TestW1AnonymousFeedbackRotatingPreauthHitsProcessBudget(t *testing.T) {
	a := newW1Anonymous(t, nil)
	for i := range 200 {
		if w := a.post(w1Post{preauth: fmt.Sprintf("browser-%d", i), body: w1Body(i)}); w.Code != 201 {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body)
		}
	}
	tokens, feedback := a.reached()
	if w := a.post(w1Post{preauth: "browser-new", body: w1Body(1000)}); w.Code != 429 {
		t.Fatalf("request over the process budget: %d", w.Code)
	}
	if gotTokens, gotFeedback := a.reached(); gotTokens != tokens || gotFeedback != feedback {
		t.Fatal("a refused request reached Auth or Feedback")
	}
}

func TestW1AnonymousFeedbackClientBucketNeedsTrustedProxy(t *testing.T) {
	// Without trusted proxies the client key would be the frontend address, so only the preauth and
	// process budgets act: 25 browsers behind one address are all admitted.
	a := newW1Anonymous(t, nil)
	for i := range 25 {
		if w := a.post(w1Post{preauth: fmt.Sprintf("browser-%d", i), body: w1Body(i)}); w.Code != 201 {
			t.Fatalf("without trusted proxies, request %d: %d", i, w.Code)
		}
	}
	// With them, one client (20 per hour) cannot rotate preauth cookies, and another client is unaffected.
	b := newW1Anonymous(t, map[string]string{"GATEWAY_TRUSTED_PROXY_CIDRS": "192.0.2.0/24"})
	for i := range 20 {
		if w := b.post(w1Post{preauth: fmt.Sprintf("browser-%d", i), body: w1Body(i), forwarded: "203.0.113.10"}); w.Code != 201 {
			t.Fatalf("trusted proxy, request %d: %d %s", i, w.Code, w.Body)
		}
	}
	if w := b.post(w1Post{preauth: "browser-fresh", body: w1Body(99), forwarded: "203.0.113.10"}); w.Code != 429 {
		t.Fatalf("21st request of one client: %d", w.Code)
	}
	if w := b.post(w1Post{preauth: "browser-fresh", body: w1Body(99), forwarded: "203.0.113.11"}); w.Code != 201 {
		t.Fatalf("another client: %d", w.Code)
	}
}
