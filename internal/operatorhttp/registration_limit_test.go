package operatorhttp

import (
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/clientaddr"
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

func TestW1RegistrationBudgetIsPerClientBehindTrustedProxy(t *testing.T) {
	now := time.Date(2026, 10, 15, 20, 0, 0, 0, time.FixedZone("Moscow", 3*60*60))
	proxy := netip.MustParsePrefix("192.0.2.0/24")
	newAPI := func(trusted ...netip.Prefix) *RemoteAPI {
		return &RemoteAPI{boundary: &API{v2: true, logger: log.New(io.Discard, "", 0), now: func() time.Time { return now }}, registration: &registrationLimits{}, clients: clientaddr.Resolver{Trusted: trusted}}
	}
	// attempt registers with a fresh browser and body, so only the per-address budget (30) can refuse.
	attempt := func(a *RemoteAPI, n int, forwarded string) bool {
		r := httptest.NewRequest("POST", "/api/v2/email-challenges", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Forwarded-For", forwarded)
		return a.admitRegistration(httptest.NewRecorder(), r, BrowserContext{PreauthToken: fmt.Sprintf("browser-%s-%d", forwarded, n)}, []byte(fmt.Sprintf(`{"commandID":"%d","purpose":"registration"}`, n)))
	}
	t.Run("two clients through one trusted proxy have separate budgets", func(t *testing.T) {
		a := newAPI(proxy)
		for n := range 30 {
			if !attempt(a, n, "203.0.113.10") {
				t.Fatalf("first client refused at %d", n)
			}
		}
		if attempt(a, 30, "203.0.113.10") {
			t.Fatal("first client over its budget admitted")
		}
		if !attempt(a, 0, "203.0.113.11") {
			t.Fatal("second client refused because of the first")
		}
	})
	t.Run("without trusted proxies the proxy address is the client", func(t *testing.T) {
		a := newAPI()
		for n := range 30 {
			if !attempt(a, n, fmt.Sprintf("203.0.113.%d", n)) {
				t.Fatalf("refused at %d", n)
			}
		}
		if attempt(a, 30, "203.0.113.200") {
			t.Fatal("spoofed header gave a separate budget")
		}
	})
	t.Run("forged header entries do not mint budgets", func(t *testing.T) {
		a := newAPI(proxy)
		for n := range 30 {
			if !attempt(a, n, fmt.Sprintf("198.51.100.%d, 203.0.113.10", n)) {
				t.Fatalf("refused at %d", n)
			}
		}
		if attempt(a, 30, "198.51.100.250, 203.0.113.10") {
			t.Fatal("forged left entry gave a separate budget")
		}
	})
	t.Run("an invalid body stays outside the budget", func(t *testing.T) {
		a := newAPI(proxy)
		for n := range 40 {
			r := httptest.NewRequest("POST", "/api/v2/email-challenges", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("X-Forwarded-For", "203.0.113.10")
			if !a.admitRegistration(httptest.NewRecorder(), r, BrowserContext{PreauthToken: fmt.Sprint(n)}, []byte(`{"purpose":`)) {
				t.Fatalf("invalid body charged at %d", n)
			}
		}
	})
}
