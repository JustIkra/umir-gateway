package operatorhttp

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// feedbackService records the posts it receives and answers like the feedback service.
type feedbackService struct {
	t      *testing.T
	mu     sync.Mutex
	posts  []*http.Request
	bodies []string
}

func (s *feedbackService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.t.Errorf("read feedback body: %v", err)
	}
	s.mu.Lock()
	s.posts, s.bodies = append(s.posts, r), append(s.bodies, string(body))
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if _, err := io.WriteString(w, `{"submissionID":"s-1"}`); err != nil {
		s.t.Errorf("write feedback response: %v", err)
	}
}

func (s *feedbackService) received() ([]*http.Request, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.posts...), append([]string(nil), s.bodies...)
}

const feedbackBody = `{"submissionID":"s-1","message":"Спасибо"}`

func (f *fixture) feedbackPost(cookie *http.Cookie, token, body string) call {
	return call{method: http.MethodPost, path: "/api/feedback", body: body, cookies: []*http.Cookie{cookie}, csrf: token, origin: f.origin}
}

func TestFeedbackForwardsAnonymousAndSessionPosts(t *testing.T) {
	f := loopbackFixture(t)
	service := &feedbackService{t: t}
	guarded := f.api.GuardFeedback(service)
	preauth, anonymousToken := f.anonymous()
	session, sessionToken := f.login()
	extra := &http.Cookie{Name: "theme", Value: "dark"}
	for name, post := range map[string]call{
		"anonymous": f.feedbackPost(preauth, anonymousToken, feedbackBody),
		"session":   f.feedbackPost(session, sessionToken, feedbackBody),
	} {
		post.cookies = append(post.cookies, extra)
		w := f.send(guarded, post)
		if w.Code != http.StatusCreated || w.Body.String() != `{"submissionID":"s-1"}` {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	posts, bodies := service.received()
	if len(posts) != 2 {
		t.Fatalf("feedback service received %d posts", len(posts))
	}
	for i, post := range posts {
		if bodies[i] != feedbackBody || post.ContentLength != int64(len(feedbackBody)) {
			t.Errorf("forwarded body %q, length %d", bodies[i], post.ContentLength)
		}
		if post.Header.Get("Cookie") != "" || post.Header.Get(CSRFHeader) != "" {
			t.Errorf("credentials reached the feedback service: %v", post.Header)
		}
	}
}

func TestFeedbackRejectsBeforeDispatch(t *testing.T) {
	f := loopbackFixture(t)
	service := &feedbackService{t: t}
	guarded := f.api.GuardFeedback(service)
	type rejection struct {
		status int
		code   string
	}
	for name, tc := range map[string]struct {
		change func(*call)
		want   rejection
	}{
		"GET":            {func(c *call) { c.method, c.body = http.MethodGet, "" }, rejection{http.StatusMethodNotAllowed, "MethodNotAllowed"}},
		"no origin":      {func(c *call) { c.origin = "" }, rejection{http.StatusForbidden, "InvalidOrigin"}},
		"foreign origin": {func(c *call) { c.origin = "http://evil.test" }, rejection{http.StatusForbidden, "InvalidOrigin"}},
		"cross-site":     {func(c *call) { c.header = map[string]string{"Sec-Fetch-Site": "cross-site"} }, rejection{http.StatusForbidden, "InvalidOrigin"}},
		"no token":       {func(c *call) { c.csrf = "" }, rejection{http.StatusForbidden, "InvalidCsrfToken"}},
		"forged token":   {func(c *call) { c.csrf = "forged" }, rejection{http.StatusForbidden, "InvalidCsrfToken"}},
		"text":           {func(c *call) { c.header = map[string]string{"Content-Type": "text/plain"} }, rejection{http.StatusUnsupportedMediaType, "UnsupportedMediaType"}},
		"too large":      {func(c *call) { c.body = `{"m":"` + strings.Repeat("a", 16<<10) + `"}` }, rejection{http.StatusRequestEntityTooLarge, "PayloadTooLarge"}},
		"not JSON":       {func(c *call) { c.body = `{"m":` }, rejection{http.StatusBadRequest, "InvalidRequest"}},
		"array":          {func(c *call) { c.body = `[]` }, rejection{http.StatusBadRequest, "InvalidRequest"}},
		"two objects":    {func(c *call) { c.body = `{} {}` }, rejection{http.StatusBadRequest, "InvalidRequest"}},
		"invalid UTF-8":  {func(c *call) { c.body = `{"m":"` + string([]byte{0xff}) + `"}` }, rejection{http.StatusBadRequest, "InvalidRequest"}},
	} {
		preauth, token := f.anonymous()
		post := f.feedbackPost(preauth, token, feedbackBody)
		tc.change(&post)
		w := f.send(guarded, post)
		wantProblem(t, w, tc.want.status, tc.want.code)
		if tc.want.status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodPost {
			t.Errorf("%s: Allow %q", name, w.Header().Get("Allow"))
		}
	}
	if posts, _ := service.received(); len(posts) != 0 {
		t.Errorf("rejected posts reached the feedback service: %d", len(posts))
	}
	// Exactly 16 KiB is accepted.
	preauth, token := f.anonymous()
	limit := `{"m":"` + strings.Repeat("a", 16<<10-8) + `"}`
	if w := f.send(guarded, f.feedbackPost(preauth, token, limit)); w.Code != http.StatusCreated {
		t.Errorf("16 KiB post: %d %s", w.Code, w.Body)
	}
}

func TestFeedbackRateLimited(t *testing.T) {
	f := loopbackFixture(t)
	service := &feedbackService{t: t}
	guarded := f.api.GuardFeedback(service)
	preauth, token := f.anonymous()
	for i := range 5 {
		if w := f.send(guarded, f.feedbackPost(preauth, token, feedbackBody)); w.Code != http.StatusCreated {
			t.Fatalf("post %d: %d %s", i+1, w.Code, w.Body)
		}
	}
	w := f.send(guarded, f.feedbackPost(preauth, token, feedbackBody))
	wantProblem(t, w, http.StatusTooManyRequests, "FeedbackRateLimited")
	if got := w.Header().Get("Retry-After"); got != "600" {
		t.Errorf("Retry-After = %q", got)
	}
	if posts, _ := service.received(); len(posts) != 5 {
		t.Errorf("feedback service received %d posts, want 5", len(posts))
	}
}
