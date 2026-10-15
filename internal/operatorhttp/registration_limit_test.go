package operatorhttp

import (
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistrationLimitsPeerBrowserReplayAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 20, 0, 0, 0, time.FixedZone("Moscow", 3*60*60))
	l := &registrationLimits{}
	body := func(n int) []byte { return []byte(fmt.Sprintf(`{"commandID":"%d","purpose":"registration"}`, n)) }
	for n := 0; n < 3; n++ {
		if wait := l.admit("192.0.2.1", "browser-a", body(n), now); wait != 0 {
			t.Fatal(wait)
		}
	}
	if wait := l.admit("192.0.2.2", "browser-a", body(3), now); wait <= 0 {
		t.Fatal("preauth bypassed by changing peer")
	}
	if wait := l.admit("192.0.2.1", "browser-a", body(0), now); wait != 0 {
		t.Fatal("recovery of original attempt throttled")
	}
	for n := 0; n < 27; n++ {
		if wait := l.admit("192.0.2.1", fmt.Sprint(n), body(0), now); wait != 0 {
			t.Fatal(wait)
		}
	}
	if wait := l.admit("192.0.2.1", "new-browser", body(0), now); wait <= 0 {
		t.Fatal("peer bypassed by rotating preauth")
	}
	if wait := l.admit("192.0.2.1", "browser-a", body(3), now.Add(10*time.Minute)); wait != 0 {
		t.Fatal("window did not expire")
	}
}
func TestRegistrationLimitHasBoundedIdentitiesAndConcurrentAdmission(t *testing.T) {
	now := time.Date(2026, 10, 15, 20, 0, 0, 0, time.FixedZone("Moscow", 3*60*60))
	l := &registrationLimits{}
	for n := 0; n < 1024; n++ {
		if l.admit(fmt.Sprint(n), fmt.Sprint(n), []byte("body"), now) != 0 {
			t.Fatal("early capacity refusal")
		}
	}
	if l.admit("new", "new", []byte("body"), now) == 0 {
		t.Fatal("unbounded identities")
	}
	l = &registrationLimits{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for n := 0; n < 100; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.admit("one-peer", fmt.Sprint(n), []byte("body"), now) == 0 {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 30 {
		t.Fatalf("admitted %d, want 30", accepted)
	}
}
func TestRegistrationHTTPAdmissionRejectsBeforeAuthAndIgnoresForwardedSpoof(t *testing.T) {
	now := time.Date(2026, 10, 15, 20, 0, 0, 0, time.FixedZone("Moscow", 3*60*60))
	a := &RemoteAPI{boundary: &API{v2: true, logger: log.New(io.Discard, "", 0), now: func() time.Time { return now }}, registration: &registrationLimits{}}
	for n := 0; n < 4; n++ {
		r := httptest.NewRequest("POST", "/api/v2/email-challenges", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", n+2))
		w := httptest.NewRecorder()
		allowed := a.admitRegistration(w, r, BrowserContext{PreauthToken: "same-browser"}, []byte(fmt.Sprintf(`{"commandID":"%d","purpose":"registration"}`, n)))
		if n < 3 && !allowed {
			t.Fatal("early refusal")
		}
		if n == 3 && (allowed || w.Code != 429 || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), `"code":"RateLimited"`)) {
			t.Fatalf("invalid refusal: %d %s", w.Code, w.Body.String())
		}
	}
}
