package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JustIkra/umir-gateway/internal/admission"
)

type ScopedLive interface {
	ServeScope(http.ResponseWriter, *http.Request, string, string, string)
}

type ScopedChanges interface {
	Append(string, []string) error
	ObserveRuntime(string, string, string) error
}

// ClientResolver names the client of a request for per-client budgets.
type ClientResolver interface{ Client(*http.Request) string }

type ScopedOptions struct {
	Admission interface {
		Admit(context.Context, admission.Rule, admission.Subjects, admission.Attempt) (admission.Verdict, error)
	}
	Clients ClientResolver
	// SummaryDeadline, SummaryConcurrency and SummaryMaxBytes bound one organization summary; zero
	// values mean the Default* constants.
	// BodyTimeout bounds reading a request body on every route except the live stream; zero means no bound.
	BodyTimeout        time.Duration
	SummaryDeadline    time.Duration
	SummaryConcurrency int
	SummaryMaxBytes    int64
	Live               ScopedLive
	Changes            ScopedChanges
	Auth               ScopedAuth
	Business           BusinessClient
	Origin             string
	SecureCookies      bool
	Now                func() time.Time
	Logger             *log.Logger
}

type ScopedAPI struct {
	options  ScopedOptions
	contract *scopeContract
	// failures receives one JSON record per 502, 503 or 504 caused by Auth or an owner.
	failures *slog.Logger
}

func NewScoped(opts ScopedOptions) (*ScopedAPI, error) {
	if opts.Auth == nil || opts.Business == nil || opts.Origin == "" || opts.Now == nil || opts.Logger == nil {
		return nil, errors.New("scoped API requires Auth, business client, browser origin, clock and logger")
	}
	c, err := contract()
	if err != nil {
		return nil, err
	}
	return &ScopedAPI{options: opts, contract: c, failures: slog.New(slog.NewJSONHandler(opts.Logger.Writer(), nil))}, nil
}

func (a *ScopedAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	op, id := a.contract.match(r.Method, r.URL.Path)
	if encoded, tenant := a.contract.match(r.Method, r.URL.EscapedPath()); encoded != nil && encoded.id == "productBatches" {
		op, id = encoded, tenant
	}
	if op == nil {
		a.writeFailure(w, r, &ScopeError{Status: 404, Code: "NotFound", Message: "unknown scoped route"})
		return
	}
	if op.id != "productBatches" && r.URL.RawPath != "" && r.URL.EscapedPath() != r.URL.Path {
		a.writeFailure(w, r, &ScopeError{Status: 400, Code: "InvalidArgument", Message: "scope path must use canonical identifiers"})
		return
	}
	diag := &requestDiag{owner: "auth", operation: op.id, start: a.options.Now()}
	if strings.Contains(op.Path, "{restaurantID}") {
		diag.restaurantID = id
	}
	r = r.WithContext(context.WithValue(r.Context(), diagKey{}, diag))
	if forbiddenScopedCredentials(r, op) {
		a.writeFailure(w, r, &ScopeError{Status: 403, Code: "Forbidden", Message: "internal credentials are not browser inputs"})
		return
	}
	limit := int64(1 << 20)
	if op.Owner == "feedback" {
		limit = 16 << 10
	}
	controller := http.NewResponseController(w)
	if op.id != "live" && a.options.BodyTimeout > 0 {
		// A stalled sender must not hold the handler open: http.Server.ReadTimeout would also cut SSE.
		// A writer without deadline support (a test recorder) is simply not bounded.
		if err := controller.SetReadDeadline(a.options.Now().Add(a.options.BodyTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			a.options.Logger.Printf("scoped body deadline failed")
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	// After a failed read the deadline stays: the server drains the unread body before it answers and
	// must not wait for a sender that stopped.
	if err == nil && op.id != "live" && a.options.BodyTimeout > 0 {
		if clearErr := controller.SetReadDeadline(time.Time{}); clearErr != nil && !errors.Is(clearErr, http.ErrNotSupported) {
			a.options.Logger.Printf("scoped body deadline reset failed")
		}
	}
	if err != nil {
		a.writeFailure(w, r, &ScopeError{Status: 400, Code: "InvalidArgument", Message: "request body is unavailable or too large"})
		return
	}
	if op.requestValidator != nil {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			a.writeFailure(w, r, &ScopeError{Status: 400, Code: "InvalidArgument", Message: "JSON is required"})
			return
		}
	}
	query, err := op.validateInput(r, body, id)
	if err != nil {
		a.writeFailure(w, r, &ScopeError{Status: 400, Code: "InvalidArgument", Message: "invalid scoped input"})
		return
	}
	session, preauth, err := a.cookies(r)
	if err != nil {
		a.writeFailure(w, r, &ScopeError{Status: 403, Code: "Unauthenticated", Message: "ambiguous browser context"})
		return
	}
	if r.Method != http.MethodGet {
		if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.options.Origin || len(r.Header.Values("Sec-Fetch-Site")) > 1 || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
			a.writeFailure(w, r, &ScopeError{Status: 403, Code: "InvalidOrigin", Message: "origin is not allowed"})
			return
		}
		if len(r.Header.Values("X-CSRF-Token")) != 1 || r.Header.Get("X-CSRF-Token") == "" {
			a.writeFailure(w, r, &ScopeError{Status: 403, Code: "InvalidCsrfToken", Message: "CSRF token is required"})
			return
		}
		if err := a.options.Auth.CheckCSRF(r.Context(), session, preauth, r.Header.Get("X-CSRF-Token")); err != nil {
			a.writeFailure(w, r, err)
			return
		}
	}
	if op.id == "live" {
		if session == "" {
			a.writeFailure(w, r, &ScopeError{Status: 403, Code: "Unauthenticated", Message: "sign in to continue"})
			return
		}
		if a.options.Live == nil {
			a.writeFailure(w, r, authUnavailable(nil))
			return
		}
		cursor := query.Get("cursor")
		if len(r.Header.Values("Last-Event-ID")) > 1 || (cursor != "" && r.Header.Get("Last-Event-ID") != "") {
			a.writeFailure(w, r, &ScopeError{Status: 400, Code: "InvalidArgument", Message: "ambiguous cursor"})
			return
		}
		if cursor == "" {
			cursor = r.Header.Get("Last-Event-ID")
		}
		if len(cursor) > 1024 {
			a.writeFailure(w, r, &ScopeError{Status: 403, Code: "Forbidden", Message: "invalid cursor"})
			return
		}
		a.options.Live.ServeScope(w, r, id, session, cursor)
		return
	}
	if op.id == "orgSummary" {
		a.summary(w, r, op, id, session, query)
		return
	}
	var decision AuthorizationResult
	var token string
	if op.id == "anonymousFeedback" {
		if failure := a.admitFeedback(r, session, preauth, body); failure != nil {
			a.writeFailure(w, r, failure)
			return
		}
		value, err := a.options.Auth.AnonymousToken(r.Context())
		if err != nil {
			a.writeFailure(w, r, err)
			return
		}
		if !a.options.Now().Before(value.ExpiresAt) {
			a.writeFailure(w, r, authUnavailable(nil))
			return
		}
		token = value.Token
	} else {
		decision, err = a.authorize(r.Context(), op, id, session, activity(r))
		if err != nil {
			a.writeFailure(w, r, err)
			return
		}
		token = decision.Token
	}
	if op.id == "prepareOrder" || op.id == "confirmOrder" {
		if failure := a.admitOrder(r, op, id, decision, body); failure != nil {
			a.writeFailure(w, r, failure)
			return
		}
	}
	privatePath := privateScopePath(op, id)
	pathValues, _ := op.pathParameters(r.URL)
	if productID := pathValues["productID"]; productID != "" {
		privatePath = strings.ReplaceAll(privatePath, "{productID}", productID)
	}
	request := BusinessRequest{Service: op.Owner, Method: r.Method, Path: privatePath, RawQuery: r.URL.RawQuery, Header: scopedHeaders(r.Header, token, RequestID(r)), Body: body}
	if op.id == "appFeedback" {
		request.Body, err = json.Marshal(struct {
			Submission json.RawMessage `json:"submission"`
			Context    feedbackContext `json:"context"`
		}{body, feedbackContext{"app", decision.UserID, decision.OrgID, decision.TenantID}})
		if err != nil {
			a.writeFailure(w, r, upstreamUnavailable(r.Method, err))
			return
		}
	}
	diag.owner = op.Owner
	response, err := a.options.Business.Do(r.Context(), request)
	if err != nil {
		a.publishChange(r, op, decision, response, err)
		a.writeFailure(w, r, upstreamUnavailable(r.Method, err))
		return
	}
	expectedEpoch := r.Header.Get("X-Umir-Runtime-Epoch")
	if op.id == "resolveOrder" {
		expectedEpoch = query.Get("runtimeEpoch")
	}
	if err := a.validateResponse(op, response, decision, expectedEpoch); err != nil {
		a.publishChange(r, op, decision, response, err)
		a.writeFailure(w, r, upstreamUnavailable(r.Method, err))
		return
	}
	if op.id == "productBatches" && response.Status == 200 {
		if err := validateProductBatchRelations(response.Body, pathValues["productID"], decision.Settings); err != nil {
			a.writeFailure(w, r, upstreamUnavailable(r.Method, err))
			return
		}
	}
	a.publishChange(r, op, decision, response, nil)
	a.observeRuntime(op, response, decision)
	for _, key := range []string{"Content-Type", "Retry-After", "Allow"} {
		for _, value := range response.Header.Values(key) {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.Status)
	if _, err := w.Write(response.Body); err != nil {
		a.options.Logger.Printf("scoped response write failed")
	}
}

type feedbackContext struct {
	Kind     string `json:"kind"`
	UserID   string `json:"userID"`
	OrgID    string `json:"orgID"`
	TenantID string `json:"tenantID"`
}

func (a *ScopedAPI) authorize(ctx context.Context, op *scopeOperation, tenant, session, activity string) (AuthorizationResult, error) {
	if session == "" {
		return AuthorizationResult{}, &ScopeError{Status: 401, Code: "Unauthenticated", Message: "a session is required"}
	}
	decision, err := a.options.Auth.Authorize(ctx, AuthorizationRequest{session, tenant, op.id, op.audiences(), activity})
	if err != nil {
		return AuthorizationResult{}, err
	}
	if decision.TenantID != tenant || !slices.Contains(decision.Permissions, op.Capability) || !a.options.Now().Before(decision.ExpiresAt) || !a.options.Now().Before(decision.Session.ExpiresAt) {
		return AuthorizationResult{}, authUnavailable(errors.New("inconsistent authorization decision"))
	}
	return decision, nil
}

func authUnavailable(cause error) *ScopeError {
	return &ScopeError{Status: 503, Code: "AuthUnavailable", Message: "authorization is unavailable", Cause: cause}
}

func activity(r *http.Request) string {
	if len(r.Header.Values("X-Umir-Activity")) == 1 && r.Header.Get("X-Umir-Activity") == "background" {
		return "background"
	}
	return "foreground"
}

func (a *ScopedAPI) cookies(r *http.Request) (string, string, error) {
	prefix := ""
	if a.options.SecureCookies {
		prefix = "__Host-"
	}
	sessionName, preauthName := prefix+"umir_operator_session", prefix+"umir_operator_preauth"
	var session, preauth string
	seen := map[string]bool{}
	for _, cookie := range r.Cookies() {
		if cookie.Name != sessionName && cookie.Name != preauthName {
			continue
		}
		if seen[cookie.Name] || cookie.Value == "" {
			return "", "", errors.New("duplicate or empty cookie")
		}
		seen[cookie.Name] = true
		if cookie.Name == sessionName {
			session = cookie.Value
		} else {
			preauth = cookie.Value
		}
	}
	return session, preauth, nil
}

func forbiddenScopedCredentials(r *http.Request, op *scopeOperation) bool {
	allowedEpoch := false
	for _, p := range op.Parameters {
		if p.In == "header" && p.Name == "X-Umir-Runtime-Epoch" {
			allowedEpoch = true
		}
	}
	for key := range r.Header {
		lower := strings.ToLower(key)
		if lower == "authorization" || lower == "proxy-authorization" || lower == "x-service-key" || (strings.HasPrefix(lower, "x-umir-") && lower != "x-umir-activity" && (lower != "x-umir-runtime-epoch" || !allowedEpoch)) {
			return true
		}
	}
	return false
}

func scopedHeaders(source http.Header, token, requestID string) http.Header {
	result := source.Clone()
	// The browser's request ID is never trusted; the owner gets the one the Gateway made.
	result.Del("X-Request-Id")
	for key := range result {
		lower := strings.ToLower(key)
		if lower == "cookie" || lower == "authorization" || lower == "proxy-authorization" || lower == "x-csrf-token" || lower == "origin" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-user") || strings.HasPrefix(lower, "x-org") || strings.HasPrefix(lower, "x-tenant") || strings.HasPrefix(lower, "x-role") || strings.HasPrefix(lower, "x-auth") || strings.HasPrefix(lower, "x-service") || (strings.HasPrefix(lower, "x-umir-") && lower != "x-umir-runtime-epoch") {
			result.Del(key)
		}
	}
	for _, line := range source.Values("Connection") {
		for _, key := range strings.Split(line, ",") {
			result.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Expect"} {
		result.Del(key)
	}
	if requestID != "" {
		result.Set("X-Request-ID", requestID)
	}
	result.Set("Authorization", "Bearer "+token)
	result.Set("Accept", "application/json")
	// A compressed owner reply would fail JSON validation and turn into 502.
	result.Set("Accept-Encoding", "identity")
	return result
}

func privateScopePath(op *scopeOperation, id string) string {
	if op.id == "appFeedback" {
		return "/internal/feedback/v2/submissions/app"
	}
	if op.id == "anonymousFeedback" {
		return "/internal/feedback/v2/submissions/anonymous"
	}
	path := strings.Replace(op.Path, "/api/v2/r/{restaurantID}/"+op.Owner, "/internal/"+op.Owner+"/v2/r/"+id, 1)
	if op.Owner == "feedback" {
		path = strings.Replace(path, "/feedback/submissions", "/submissions", 1)
		path = strings.Replace(path, "/feedback/export", "/export", 1)
	}
	return path
}

func (a *ScopedAPI) validateResponse(op *scopeOperation, response BusinessResponse, decision AuthorizationResult, expectedEpoch string) error {
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return Classed(ClassInvalidResponse, errors.New("invalid upstream content type"))
	}
	if response.Status >= 400 && response.Status <= 599 {
		if err := ValidateScopeWire("Error", response.Body); err != nil {
			return Classed(ClassSchema, err)
		}
		var failure struct {
			Details struct{ ScopeID string } `json:"details"`
		}
		if err := json.Unmarshal(response.Body, &failure); err != nil {
			return err
		}
		if scope := failure.Details.ScopeID; scope != "" && scope != decision.TenantID && scope != decision.OrgID {
			return Classed(ClassScopeMismatch, errors.New("error scope mismatch"))
		}
		return nil
	}
	expected := 200
	if op.Owner == "feedback" && op.Method == http.MethodPost {
		expected = 201
	}
	if response.Status != expected {
		return Classed(ClassUpstreamStatus, errors.New("unexpected upstream status"))
	}
	value, err := decodeScopedValues(response.Body, op.id == "supplySuggestions")
	if err != nil {
		return err
	}
	if err := op.responseValidator.Validate(value); err != nil {
		return Classed(ClassSchema, err)
	}
	if op.id != "anonymousFeedback" {
		epoch := ""
		if op.Owner == "warehouse" {
			epoch = expectedEpoch
		}
		if err := validateNestedScope(value, decision.OrgID, decision.TenantID, epoch); err != nil {
			return err
		}
	}
	var envelope struct {
		Context struct{ OrgID, TenantID, RuntimeEpoch string } `json:"context"`
		Scope   feedbackContext                                `json:"scope"`
	}
	if err := json.Unmarshal(response.Body, &envelope); err != nil {
		return err
	}
	if op.id == "anonymousFeedback" {
		if envelope.Scope.Kind != "anonymous" || envelope.Scope.OrgID != "" || envelope.Scope.TenantID != "" || envelope.Scope.UserID != "" {
			return Classed(ClassScopeMismatch, errors.New("scoped anonymous result"))
		}
		return nil
	}
	if op.Owner == "feedback" && op.id != "appFeedback" {
		var list struct {
			TenantID string `json:"tenantID"`
			Items    []struct {
				Scope feedbackContext `json:"scope"`
			} `json:"items"`
		}
		if err := json.Unmarshal(response.Body, &list); err != nil {
			return err
		}
		if list.TenantID != decision.TenantID {
			return Classed(ClassScopeMismatch, errors.New("feedback list tenant mismatch"))
		}
		for _, item := range list.Items {
			if item.Scope.Kind != "app" || item.Scope.OrgID != decision.OrgID || item.Scope.TenantID != decision.TenantID {
				return Classed(ClassScopeMismatch, errors.New("feedback item scope mismatch"))
			}
		}
		return nil
	}
	if op.id == "appFeedback" {
		if envelope.Scope != (feedbackContext{"app", decision.UserID, decision.OrgID, decision.TenantID}) {
			return Classed(ClassScopeMismatch, errors.New("feedback scope mismatch"))
		}
		return nil
	}
	if envelope.Context.TenantID != "" && (envelope.Context.TenantID != decision.TenantID || envelope.Context.OrgID != decision.OrgID || (expectedEpoch != "" && envelope.Context.RuntimeEpoch != expectedEpoch)) {
		return Classed(ClassScopeMismatch, errors.New("business scope mismatch"))
	}
	if op.id == "supplySuggestions" || op.id == "recommendations" {
		return validatePlanningCapture(op.id, response.Body, decision.Settings)
	}
	return nil
}

func validateNestedScope(value any, orgID, tenantID, epoch string) error {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "orgID" || key == "tenantID" || key == "runtimeEpoch" && epoch != "" {
				text, ok := child.(string)
				expected := orgID
				switch key {
				case "tenantID":
					expected = tenantID
				case "runtimeEpoch":
					expected = epoch
				}
				if !ok || text != expected {
					return Classed(ClassScopeMismatch, errors.New("nested scope mismatch"))
				}
			}
			if err := validateNestedScope(child, orgID, tenantID, epoch); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range node {
			if err := validateNestedScope(child, orgID, tenantID, epoch); err != nil {
				return err
			}
		}
	}
	return nil
}

func upstreamUnavailable(method string, cause error) *ScopeError {
	status := 502
	if errors.Is(cause, context.DeadlineExceeded) {
		status = 504
	}
	outcome := "unknown"
	if method == http.MethodGet {
		outcome = "unavailable"
	}
	return &ScopeError{Status: status, Code: "UpstreamUnavailable", Outcome: outcome, Message: "upstream response is unavailable", Cause: cause}
}

func (a *ScopedAPI) admitFeedback(r *http.Request, session, preauth string, body []byte) *ScopeError {
	if a.options.Admission == nil {
		return nil
	}
	client := ""
	if a.options.Clients != nil {
		client = a.options.Clients.Client(r)
	}
	if preauth == "" {
		preauth = "session:" + session
	}
	sum := sha256.Sum256(append(append([]byte(preauth), 0), body...))
	fingerprint := hex.EncodeToString(sum[:])
	return a.admit(r, admission.RuleFeedback, admission.Subjects{Preauth: preauth, Client: client, Global: true}, admission.Attempt{ID: fingerprint, Fingerprint: fingerprint})
}

func (a *ScopedAPI) admitOrder(r *http.Request, op *scopeOperation, restaurant string, decision AuthorizationResult, body []byte) *ScopeError {
	if a.options.Admission == nil {
		return nil
	}
	canonical, err := canonicalAdmissionJSON(body)
	if err != nil {
		return &ScopeError{Status: http.StatusBadRequest, Code: "InvalidArgument", Outcome: "not_committed", Message: "invalid order input", Cause: err}
	}
	var input struct {
		CommandID string `json:"commandID"`
	}
	_ = json.Unmarshal(body, &input)
	identity := []byte(strings.Join([]string{"order", op.id, decision.OrgID, decision.UserID, restaurant, input.CommandID}, "\x00"))
	if input.CommandID == "" {
		identity = append(identity, 0)
		identity = append(identity, canonical...)
	}
	sum := sha256.Sum256(identity)
	return a.admit(r, admission.RuleOrder, admission.Subjects{User: decision.UserID, Restaurant: restaurant}, admission.Attempt{ID: hex.EncodeToString(sum[:]), Fingerprint: string(canonical)})
}

func canonicalAdmissionJSON(body []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("multiple JSON values")
	}
	return json.Marshal(value)
}

func (a *ScopedAPI) admit(r *http.Request, rule admission.Rule, subjects admission.Subjects, attempt admission.Attempt) *ScopeError {
	verdict, err := a.options.Admission.Admit(r.Context(), rule, subjects, attempt)
	if err != nil {
		if errors.Is(err, admission.ErrConflict) {
			return &ScopeError{Status: http.StatusConflict, Code: "CommandConflict", Outcome: "not_committed", Message: "command identity conflicts with an earlier request"}
		}
		return &ScopeError{Status: http.StatusServiceUnavailable, Code: "ServiceUnavailable", Outcome: "not_committed", Message: "request admission is unavailable", Cause: err}
	}
	if !verdict.Allowed {
		return &ScopeError{Status: http.StatusTooManyRequests, Code: "RateLimited", Outcome: "not_committed", Message: "request limit reached", Retryable: true, RetryAfter: admission.RetryAfterSeconds(verdict.RetryAfter)}
	}
	return nil
}

func (a *ScopedAPI) writeFailure(w http.ResponseWriter, r *http.Request, err error) {
	var failure *ScopeError
	if !errors.As(err, &failure) {
		failure = authUnavailable(err)
	}
	copy := *failure
	if copy.Outcome == "" {
		copy.Outcome = "not_committed"
		if r.Method == http.MethodGet {
			copy.Outcome = "unavailable"
		}
	}
	if copy.Status == http.StatusBadGateway || copy.Status == http.StatusServiceUnavailable || copy.Status == http.StatusGatewayTimeout {
		diag := &requestDiag{owner: "auth"}
		if known, ok := r.Context().Value(diagKey{}).(*requestDiag); ok {
			diag = known
		}
		a.logFailure(r.Context(), diag.owner, diag.operation, diag.restaurantID, copy.Status, err, a.options.Now().Sub(diag.start))
	}
	copy.Cause = nil
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if copy.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(copy.RetryAfter))
		if _, set := copy.Details["retryAfterSeconds"]; !set {
			copy.Details = maps.Clone(copy.Details)
			if copy.Details == nil {
				copy.Details = map[string]any{}
			}
			copy.Details["retryAfterSeconds"] = copy.RetryAfter
		}
	}
	w.WriteHeader(copy.Status)
	if err := json.NewEncoder(w).Encode(&copy); err != nil {
		a.options.Logger.Printf("scoped error write failed")
	}
}

func equalJSON(a, b json.RawMessage) bool {
	left, leftErr := decodeScoped(a)
	right, rightErr := decodeScoped(b)
	if leftErr != nil || rightErr != nil {
		return false
	}
	l, err := json.Marshal(left)
	if err != nil {
		return false
	}
	r, err := json.Marshal(right)
	return err == nil && bytes.Equal(l, r)
}

func (a *ScopedAPI) publishChange(r *http.Request, op *scopeOperation, decision AuthorizationResult, response BusinessResponse, err error) {
	if a.options.Changes == nil || (op.Owner != "warehouse" && op.Owner != "serving") || decision.TenantID == "" {
		return
	}
	changed := r.Method != http.MethodGet && (err != nil || response.Status < 400 || response.Status >= 500)
	if r.Method != http.MethodGet && err == nil && response.Status >= 400 && response.Status < 500 {
		var failure ScopeError
		if json.Unmarshal(response.Body, &failure) == nil && (failure.Outcome == "unknown" || failure.Outcome == "indeterminate") {
			changed = true
		}
	}
	if op.Owner == "warehouse" && response.Header.Get("X-Umir-Invalidation-Required") == "true" {
		changed = true
	}
	if changed {
		if err := a.options.Changes.Append(decision.TenantID, []string{"catalog", "stock", "menu", "orders", "analytics"}); err != nil {
			a.options.Logger.Print("scoped journal publication failed")
		}
	}
}

func (a *ScopedAPI) observeRuntime(op *scopeOperation, response BusinessResponse, decision AuthorizationResult) {
	if a.options.Changes == nil || (op.Owner != "warehouse" && op.Owner != "serving") {
		return
	}
	var value struct {
		Context struct {
			RuntimeEpoch string `json:"runtimeEpoch"`
		} `json:"context"`
	}
	if response.Status == 200 {
		if err := json.Unmarshal(response.Body, &value); err != nil {
			return
		}
	} else if response.Header.Get("X-Umir-Invalidation-Required") == "true" {
		value.Context.RuntimeEpoch = response.Header.Get("X-Umir-Runtime-Epoch")
	}
	epoch := value.Context.RuntimeEpoch
	if data, err := json.Marshal(epoch); err != nil || ValidateScopeWire("Epoch", data) != nil {
		return
	}
	if err := a.options.Changes.ObserveRuntime(decision.TenantID, op.Owner, epoch); err != nil {
		a.options.Logger.Print("scoped runtime observation failed")
	}
}

// requestDiag is what a failure record needs to know about the request being served.
type requestDiag struct {
	owner, operation, restaurantID string
	start                          time.Time
}
type diagKey struct{}

// ownedError says which side a failure of a summary report came from.
type ownedError struct {
	owner string
	err   error
}

func (e *ownedError) Error() string { return e.err.Error() }
func (e *ownedError) Unwrap() error { return e.err }

// logFailure writes one structured record of an upstream failure. It names the class of the cause and
// leaves out its text, addresses, cookies, tokens, bodies and client addresses.
func (a *ScopedAPI) logFailure(ctx context.Context, owner, operation, restaurantID string, status int, err error, took time.Duration) {
	a.failures.LogAttrs(ctx, slog.LevelWarn, "upstream_failure",
		slog.String("request_id", RequestIDFromContext(ctx)),
		slog.String("owner", owner),
		slog.String("operation", operation),
		slog.String("restaurant_id", restaurantID),
		slog.Int("status", status),
		slog.String("class", FailureClass(err)),
		slog.Int64("duration_ms", took.Milliseconds()))
}
