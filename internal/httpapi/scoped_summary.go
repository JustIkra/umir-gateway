package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type scopeSummaryItem struct {
	RestaurantID string          `json:"restaurantID"`
	Status       string          `json:"status"`
	Stock        json.RawMessage `json:"stock,omitempty"`
	Movements    json.RawMessage `json:"movements,omitempty"`
	Error        *ScopeError     `json:"error,omitempty"`
}

func (a *ScopedAPI) summary(w http.ResponseWriter, r *http.Request, op *scopeOperation, orgID, session string, query url.Values) {
	if session == "" {
		a.writeFailure(w, r, &ScopeError{Status: 401, Code: "Unauthenticated", Message: "a session is required"})
		return
	}
	for _, tenant := range query["restaurantID"] {
		access, err := a.options.Auth.AccessCheck(r.Context(), AccessCheckRequest{session, tenant, op.id})
		if err != nil {
			a.writeFailure(w, r, err)
			return
		}
		if access.OrgID != orgID || access.RestaurantID != tenant || !slices.Contains(access.OrgRoles, "Admin") || !slices.Contains(access.Permissions, "org.summary.read") {
			a.writeFailure(w, r, &ScopeError{Status: 403, Code: "Forbidden", Message: "summary scopes are not authorized"})
			return
		}
	}
	items := make([]scopeSummaryItem, 0, len(query["restaurantID"]))
	successes := 0
	for _, tenant := range query["restaurantID"] {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		stock, err := a.completeReport(ctx, r, session, orgID, tenant, "analyticsstock", query)
		var movements json.RawMessage
		if err == nil {
			movements, err = a.completeReport(ctx, r, session, orgID, tenant, "analyticsmovements", query)
		}
		cancel()
		item := scopeSummaryItem{RestaurantID: tenant, Status: "unavailable"}
		if err != nil {
			var failure *ScopeError
			if !errors.As(err, &failure) {
				failure = upstreamUnavailable(http.MethodGet, err)
			}
			copy := *failure
			copy.Status = 0
			copy.Cause = nil
			copy.Outcome = "unavailable"
			item.Error = &copy
		} else {
			item.Status = "ok"
			item.Stock = stock
			item.Movements = movements
			successes++
		}
		items = append(items, item)
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
	}{orgID, a.options.Now().Format(time.RFC3339Nano), status, items}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		a.options.Logger.Printf("summary response write failed")
	}
}

func (a *ScopedAPI) completeReport(ctx context.Context, r *http.Request, session, orgID, tenant, operation string, summaryQuery url.Values) (json.RawMessage, error) {
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
