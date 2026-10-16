package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

type scopeSummaryItem struct {
	RestaurantID string          `json:"restaurantID"`
	Status       string          `json:"status"`
	Stock        json.RawMessage `json:"stock,omitempty"`
	Movements    json.RawMessage `json:"movements,omitempty"`
	Error        *ScopeError     `json:"error,omitempty"`
}

// Defaults of the summary limits, used when the options leave them zero; the configuration sets them.
const (
	DefaultSummaryDeadline    = 20 * time.Second
	DefaultSummaryConcurrency = 4
	DefaultSummaryMaxBytes    = 64 << 20
)

// summaryPerRestaurant bounds one restaurant's reports inside the overall deadline.
const summaryPerRestaurant = 5 * time.Second

var moscow = time.FixedZone("Europe/Moscow", 3*60*60)

func (a *ScopedAPI) summaryLimits() (time.Duration, int, int64) {
	deadline, concurrency, maxBytes := a.options.SummaryDeadline, a.options.SummaryConcurrency, a.options.SummaryMaxBytes
	if deadline <= 0 {
		deadline = DefaultSummaryDeadline
	}
	if concurrency <= 0 {
		concurrency = DefaultSummaryConcurrency
	}
	if maxBytes <= 0 {
		maxBytes = DefaultSummaryMaxBytes
	}
	return deadline, concurrency, maxBytes
}

// byteBudget is the report bytes one summary request may hold in total.
type byteBudget struct {
	mu        sync.Mutex
	remaining int64
}

// reservation is what one restaurant took from the budget; it is given back when the restaurant fails.
type reservation struct {
	budget *byteBudget
	taken  int64
}

func (r *reservation) take(n int) bool {
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	if int64(n) > r.budget.remaining {
		return false
	}
	r.budget.remaining -= int64(n)
	r.taken += int64(n)
	return true
}

func (r *reservation) release() {
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	r.budget.remaining += r.taken
	r.taken = 0
}

// forEachBounded runs work for every index with at most limit calls at once and waits for all of them.
func forEachBounded(n, limit int, work func(int)) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, limit)
	for i := range n {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			work(i)
		})
	}
	wg.Wait()
}

func (a *ScopedAPI) summary(w http.ResponseWriter, r *http.Request, op *scopeOperation, orgID, session string, query url.Values) {
	if session == "" {
		a.writeFailure(w, r, &ScopeError{Status: 401, Code: "Unauthenticated", Message: "a session is required"})
		return
	}
	deadline, concurrency, maxBytes := a.summaryLimits()
	ctx, cancel := context.WithTimeout(r.Context(), deadline)
	defer cancel()
	tenants := query["restaurantID"]
	if err := a.checkSummaryAccess(ctx, op, orgID, session, tenants, concurrency); err != nil {
		a.writeFailure(w, r, err)
		return
	}
	items := make([]scopeSummaryItem, len(tenants))
	budget := &byteBudget{remaining: maxBytes}
	forEachBounded(len(tenants), concurrency, func(i int) {
		items[i] = a.summaryItem(ctx, r, session, orgID, tenants[i], query, &reservation{budget: budget})
	})
	successes := 0
	for _, item := range items {
		if item.Status == "ok" {
			successes++
		}
	}
	status := "partial"
	if successes == len(items) {
		status = "complete"
	} else if successes == 0 {
		status = "unavailable"
	}
	result := struct {
		OrgID       string             `json:"orgID"`
		EvaluatedAt string             `json:"evaluatedAt"`
		Status      string             `json:"status"`
		Restaurants []scopeSummaryItem `json:"restaurants"`
	}{orgID, a.options.Now().In(moscow).Format(time.RFC3339Nano), status, items}
	data, err := json.Marshal(result)
	if err == nil {
		err = ValidateScopeWire("OrgSummary", data)
	}
	if err != nil {
		a.writeFailure(w, r, upstreamUnavailable(http.MethodGet, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(append(data, '\n')); err != nil {
		a.options.Logger.Printf("summary response write failed")
	}
}

// checkSummaryAccess authorizes every requested restaurant before any business call. The first failure
// ends the whole request and cancels the checks still running.
func (a *ScopedAPI) checkSummaryAccess(ctx context.Context, op *scopeOperation, orgID, session string, tenants []string, concurrency int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var first error
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if first == nil {
			first = err
			cancel()
		}
	}
	forEachBounded(len(tenants), concurrency, func(i int) {
		if ctx.Err() != nil {
			return
		}
		tenant := tenants[i]
		access, err := a.options.Auth.AccessCheck(ctx, AccessCheckRequest{session, tenant, op.id})
		switch {
		case err != nil:
			fail(err)
		case access.OrgID != orgID || access.RestaurantID != tenant || !slices.Contains(access.OrgRoles, "Admin") || !slices.Contains(access.Permissions, "org.summary.read"):
			fail(&ScopeError{Status: 403, Code: "Forbidden", Message: "summary scopes are not authorized"})
		}
	})
	if first == nil && ctx.Err() != nil {
		first = authUnavailable(ctx.Err())
	}
	return first
}

// summaryItem reads both reports of one restaurant; any failure makes just this restaurant unavailable.
func (a *ScopedAPI) summaryItem(ctx context.Context, r *http.Request, session, orgID, tenant string, query url.Values, held *reservation) scopeSummaryItem {
	ctx, cancel := context.WithTimeout(ctx, summaryPerRestaurant)
	defer cancel()
	stock, err := a.completeReport(ctx, r, session, orgID, tenant, "analyticsstock", query, held)
	var movements json.RawMessage
	if err == nil {
		movements, err = a.completeReport(ctx, r, session, orgID, tenant, "analyticsmovements", query, held)
	}
	if err == nil {
		return scopeSummaryItem{RestaurantID: tenant, Status: "ok", Stock: stock, Movements: movements}
	}
	held.release()
	var failure *ScopeError
	if !errors.As(err, &failure) {
		failure = upstreamUnavailable(http.MethodGet, err)
	}
	copy := *failure
	copy.Status = 0
	copy.Cause = nil
	copy.Outcome = "unavailable"
	return scopeSummaryItem{RestaurantID: tenant, Status: "unavailable", Error: &copy}
}

func (a *ScopedAPI) completeReport(ctx context.Context, r *http.Request, session, orgID, tenant, operation string, summaryQuery url.Values, held *reservation) (json.RawMessage, error) {
	op := a.contract.Operations[operation]
	query := url.Values{"expectedSettingsVersion": summaryQuery["expectedSettingsVersion"], "limit": []string{"500"}}
	for _, key := range []string{"riskHours", "fromDate", "throughDate"} {
		if (operation == "analyticsstock" && key == "riskHours") || (operation == "analyticsmovements" && key != "riskHours") {
			if values, ok := summaryQuery[key]; ok {
				query[key] = values
			}
		}
	}
	var first map[string]json.RawMessage
	var rows []json.RawMessage
	cursors := map[string]bool{}
	type rowKey struct{ ProductID, BaseUnit string }
	seenRows := map[rowKey]bool{}
	previous := rowKey{}
	hasPrevious := false
	const maxReportBytes = 32 << 20
	bytesUsed := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		decision, err := a.authorize(ctx, op, tenant, session, activity(r))
		if err != nil {
			return nil, err
		}
		if decision.OrgID != orgID {
			return nil, &ScopeError{Status: 403, Code: "Forbidden", Outcome: "unavailable", Message: "summary scope changed"}
		}
		response, err := a.options.Business.Do(ctx, BusinessRequest{Service: "warehouse", Method: http.MethodGet, Path: privateScopePath(op, tenant), RawQuery: query.Encode(), Header: scopedHeaders(r.Header, decision.Token)})
		a.publishChange(r, op, decision, response, err)
		if err != nil {
			return nil, err
		}
		if err := a.validateResponse(op, response, decision, ""); err != nil {
			return nil, err
		}
		a.observeRuntime(op, response, decision)
		if response.Status != 200 {
			var failure ScopeError
			if err := json.Unmarshal(response.Body, &failure); err != nil {
				return nil, err
			}
			failure.Status = response.Status
			return nil, &failure
		}
		bytesUsed += len(response.Body)
		if bytesUsed > maxReportBytes {
			return nil, errors.New("complete report exceeds bounded response capacity")
		}
		if !held.take(len(response.Body)) {
			return nil, &ScopeError{Status: 503, Code: "UpstreamUnavailable", Outcome: "unavailable", Message: "summary size budget is exhausted"}
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(response.Body, &fields); err != nil {
			return nil, err
		}
		var identity struct {
			TenantID, Epoch, StateVersion string
			Settings                      ScopeSettings
		}
		var context struct {
			TenantID, RuntimeEpoch, StateVersion string
			Settings                             ScopeSettings
		}
		if err := json.Unmarshal(fields["page"], &identity); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(fields["context"], &context); err != nil {
			return nil, err
		}
		if identity.TenantID != tenant || identity.Epoch != context.RuntimeEpoch || identity.StateVersion != context.StateVersion || identity.Settings != context.Settings || identity.Settings != decision.Settings {
			return nil, errors.New("report identity mismatch")
		}
		if first == nil {
			first = fields
		} else {
			for key, value := range first {
				if key != "items" && key != "nextCursor" && !equalJSON(value, fields[key]) {
					return nil, errors.New("report page metadata drift")
				}
			}
		}
		var pageRows []json.RawMessage
		if err := json.Unmarshal(fields["items"], &pageRows); err != nil {
			return nil, err
		}
		for _, row := range pageRows {
			var item struct{ ProductID, BaseUnit string }
			if err := json.Unmarshal(row, &item); err != nil {
				return nil, err
			}
			key := rowKey{item.ProductID, item.BaseUnit}
			comparison := strings.Compare(previous.ProductID, key.ProductID)
			if comparison == 0 {
				comparison = strings.Compare(previous.BaseUnit, key.BaseUnit)
			}
			if seenRows[key] || hasPrevious && comparison >= 0 {
				return nil, errors.New("duplicate or unordered report row")
			}
			seenRows[key] = true
			previous = key
			hasPrevious = true
			rows = append(rows, row)
		}
		var next string
		if raw, ok := fields["nextCursor"]; ok {
			if err := json.Unmarshal(raw, &next); err != nil {
				return nil, err
			}
		}
		if next == "" {
			break
		}
		if len(pageRows) == 0 || cursors[next] {
			return nil, errors.New("empty page or repeated report cursor")
		}
		cursors[next] = true
		query.Set("cursor", next)
	}
	data, err := json.Marshal(rows)
	if err != nil {
		return nil, err
	}
	if rows == nil {
		data = []byte("[]")
	}
	first["items"] = data
	delete(first, "nextCursor")
	return json.Marshal(first)
}
