package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// These tests lock the error enum of the scoped boundary: the codes the owners are about to use must
// cross it unchanged, and a code outside the enum must stay a 502. A failure after `make sync-contract`
// means the schema and the owners disagree.

const w1ProductBody = `{"commandID":"a","productID":"P","name":"A","baseUnit":"g"}`
const w1OrderBody = `{"commandID":"saved","proposalID":"proposal"}`

type w1OwnerError struct {
	status        int
	code, outcome string
	retryAfter    int
}

func (e w1OwnerError) serve(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{"code": e.code, "outcome": e.outcome, "message": "owner refusal", "retryable": e.status == 429 || e.status == 503}
		if e.retryAfter > 0 {
			w.Header().Set("Retry-After", "7")
			body["details"] = map[string]any{"retryAfterSeconds": e.retryAfter}
		}
		w.WriteHeader(e.status)
		writeScopedJSON(t, w, body)
	}
}

type w1Reply struct {
	Code, Outcome string
	Details       struct{ RetryAfterSeconds int }
}

func w1Cross(t *testing.T, owner w1OwnerError, path, body string) (int, w1Reply, http.Header) {
	t.Helper()
	f := newScopedFixture(t)
	f.peer = owner.serve(t)
	w := f.request("POST", "/api/v2/r/"+scopedRestaurant+"/"+path, body, nil)
	var reply w1Reply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatalf("response is not an error body: %d %s", w.Code, w.Body)
	}
	return w.Code, reply, w.Header()
}

func TestW1BoundaryPassesCommandConflictFromServingWarehouseAndAuth(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"warehouse", "warehouse/products", w1ProductBody},
		{"serving", "serving/order-confirmations", w1OrderBody},
	} {
		for _, outcome := range []string{"not_committed", "unknown"} {
			t.Run(tc.name+"/"+outcome, func(t *testing.T) {
				status, reply, _ := w1Cross(t, w1OwnerError{status: 409, code: "CommandConflict", outcome: outcome}, tc.path, tc.body)
				if status != 409 || reply.Code != "CommandConflict" || reply.Outcome != outcome {
					t.Fatalf("%d %+v", status, reply)
				}
			})
		}
	}
	t.Run("auth through the facade", func(t *testing.T) {
		app := authFacadeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			writeScopedJSON(t, w, map[string]any{"code": "CommandConflict", "outcome": "unknown", "message": "the result of the command is no longer known", "retryable": false})
		}))
		w := facadeRequest(app, "POST", "/api/v2/sessions/logout-all", `{"commandID":"same"}`)
		var reply w1Reply
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != 409 || reply.Code != "CommandConflict" || reply.Outcome != "unknown" {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
}

func TestW1BoundaryPassesLimitExceededAndInvalidArgumentOnOrderLimits(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{{409, "LimitExceeded"}, {400, "InvalidArgument"}} {
		t.Run(tc.code, func(t *testing.T) {
			status, reply, _ := w1Cross(t, w1OwnerError{status: tc.status, code: tc.code, outcome: "not_committed"}, "serving/order-confirmations", w1OrderBody)
			if status != tc.status || reply.Code != tc.code || reply.Outcome != "not_committed" {
				t.Fatalf("%d %+v", status, reply)
			}
		})
	}
}

func TestW1BoundaryPassesServiceUnavailableAndRateLimitedWithRetryAfterSeconds(t *testing.T) {
	for _, tc := range []struct {
		name, path, body, outcome string
		status                    int
		code                      string
		retryAfter                int
	}{
		{"service unavailable for a write", "warehouse/products", w1ProductBody, "not_committed", 503, "ServiceUnavailable", 0},
		{"rate limited", "warehouse/products", w1ProductBody, "not_committed", 429, "RateLimited", 7},
		{"rate limited order", "serving/order-confirmations", w1OrderBody, "not_committed", 429, "RateLimited", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, reply, header := w1Cross(t, w1OwnerError{status: tc.status, code: tc.code, outcome: tc.outcome, retryAfter: tc.retryAfter}, tc.path, tc.body)
			if status != tc.status || reply.Code != tc.code || reply.Outcome != tc.outcome || reply.Details.RetryAfterSeconds != tc.retryAfter {
				t.Fatalf("%d %+v", status, reply)
			}
			if tc.retryAfter > 0 && header.Get("Retry-After") != "7" {
				t.Fatalf("Retry-After lost: %v", header)
			}
		})
	}
	t.Run("service unavailable for a read", func(t *testing.T) {
		f := newScopedFixture(t)
		f.peer = w1OwnerError{status: 503, code: "ServiceUnavailable", outcome: "unavailable"}.serve(t)
		w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", nil)
		var reply w1Reply
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != 503 || reply.Code != "ServiceUnavailable" || reply.Outcome != "unavailable" {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
}

func TestW1BoundaryTurnsUnknownErrorCodeInto502(t *testing.T) {
	for _, code := range []string{"CommandIdentityConflict", "SomethingNew"} {
		t.Run(code, func(t *testing.T) {
			f := newScopedFixture(t)
			f.peer = w1OwnerError{status: 409, code: code, outcome: "not_committed"}.serve(t)
			w := f.request("POST", "/api/v2/r/"+scopedRestaurant+"/warehouse/products", w1ProductBody, nil)
			if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), code) {
				t.Fatalf("code outside the enum: %d %s", w.Code, w.Body)
			}
		})
	}
}
