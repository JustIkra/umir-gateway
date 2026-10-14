package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestG2SuccessfulFeedbackUsesExactVerifiedScope(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		t.Run(map[bool]string{false: "app", true: "anonymous"}[anonymous], func(t *testing.T) {
			f := newScopedFixture(t)
			f.peer = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Set-Cookie", "umir_operator_session=upstream-secret")
				w.Header().Set("Authorization", "Bearer private-secret")
				scope := map[string]any{"kind": "anonymous"}
				if !anonymous {
					scope = map[string]any{"kind": "app", "userID": "11111111-1111-4111-8111-111111111111", "orgID": scopedOrg, "tenantID": scopedRestaurant}
				}
				w.WriteHeader(201)
				writeScopedJSON(t, w, map[string]any{"receipt": map[string]any{"submissionID": "77777777-7777-4777-8777-777777777777", "receivedAt": "2026-10-13T01:00:00+03:00"}, "scope": scope, "state": "accepted"})
			}
			path := "/api/v2/r/" + scopedRestaurant + "/feedback"
			if anonymous {
				path = "/api/v2/feedback/anonymous"
			}
			body := `{"submissionID":"77777777-7777-4777-8777-777777777777","name":"A","email":"a@example.test","message":"M","consent":{"accepted":true,"documentVersion":"1"}}`
			w := f.request("POST", path, body, nil)
			if w.Code != 201 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Authorization") != "" || !strings.Contains(w.Body.String(), "2026-10-13T01:00:00+03:00") {
				t.Fatalf("successful feedback refused/leaked=%d %s headers=%v", w.Code, w.Body, w.Header())
			}
		})
	}
}

func TestG2SuccessfulStockRetainsExactValuesAndDropsPrivateMetadata(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Umir-Committed-Version", "4")
		w.Header().Set("X-Umir-Invalidation-Required", "true")
		w.Header().Set("X-Umir-Runtime-Epoch", scopedEpoch)
		page := summaryPage(scopedRestaurant, "stock", true)
		writeScopedJSON(t, w, map[string]any{"context": page["context"], "result": map[string]any{"items": page["items"]}})
	}
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/inventory", "", map[string]string{"X-Umir-Activity": "background"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "9007199254740993") || w.Header().Get("X-Umir-Committed-Version") != "" || f.authorizations[0]["activity"] != "background" {
		t.Fatalf("valid stock result=%d %s headers=%v", w.Code, w.Body, w.Header())
	}
}

func TestG2QueryRejectsInvalidUTF8(t *testing.T) {
	f := newScopedFixture(t)
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/dish?dishID=%FF", "", nil)
	if w.Code != 400 || len(f.requests) != 0 {
		t.Fatalf("invalid query dispatched=%d %s", w.Code, w.Body)
	}
}

func TestG2NestedRetainedOutcomeCannotExposeAnotherTenant(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		outer := summaryPage(scopedRestaurant, "stock", true)["context"]
		nested := summaryPage(scopedOtherRestaurant, "stock", true)["context"]
		writeScopedJSON(t, w, map[string]any{"context": outer, "commandID": "saved", "batchID": "B1", "commandFingerprint": strings.Repeat("a", 64), "observation": map[string]any{"state": "committed", "outcome": "committed", "result": map[string]any{"context": nested, "result": map[string]any{"batchID": "B1", "productID": "P1", "writtenOffQuantity": "9007199254740993", "baseUnit": "g", "actorUserID": "11111111-1111-4111-8111-111111111111", "confirmedAt": "2026-10-13T01:00:00+03:00", "eventID": "writeoff-fact"}}}})
	}
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/writeoffs/commands?commandID=saved&batchID=B1", "", map[string]string{"X-Umir-Runtime-Epoch": scopedEpoch})
	if w.Code != 502 || !strings.Contains(w.Body.String(), `"outcome":"unavailable"`) {
		t.Fatalf("nested tenant exposed=%d %s", w.Code, w.Body)
	}
}

func TestG2FeedbackReadRejectsAnotherTenant(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeScopedJSON(t, w, map[string]any{"tenantID": scopedOtherRestaurant, "items": []any{}})
	}
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/feedback/submissions", "", nil)
	if w.Code != 502 || !strings.Contains(w.Body.String(), `"outcome":"unavailable"`) {
		t.Fatalf("cross tenant feedback read=%d %s", w.Code, w.Body)
	}
}

func TestG2MalformedBusinessMutationRemainsUnknownAndNeverRetries(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if _, err := w.Write([]byte(`{"context":`)); err != nil {
			t.Error(err)
		}
	}
	w := f.request("POST", "/api/v2/r/"+scopedRestaurant+"/warehouse/products", `{"commandID":"unknown-once","productID":"01","name":"Exact","baseUnit":"g"}`, nil)
	if w.Code != 502 || !strings.Contains(w.Body.String(), `"outcome":"unknown"`) || len(f.requests) != 1 {
		t.Fatalf("unknown outcome=%d %s dispatch=%d", w.Code, w.Body, len(f.requests))
	}
}

func TestG2RawQueryIsPreservedAfterValidation(t *testing.T) {
	f := newScopedFixture(t)
	query := "dishID=opaque%2f%D0%B4%2B+%25"
	w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/dish?"+query, "", nil)
	if w.Code != 409 || len(f.requests) != 1 || f.requests[0].Query != query {
		t.Fatalf("query rewritten=%d %v", w.Code, f.requests)
	}
}

func TestG2ExactFeedbackRetriesKeepTrustedNamespace(t *testing.T) {
	f := newScopedFixture(t)
	body := `{"submissionID":"77777777-7777-4777-8777-777777777777","name":"A","email":"a@example.test","message":"M","consent":{"accepted":true,"documentVersion":"1"}}`
	for _, tenant := range []string{scopedRestaurant, scopedRestaurant, scopedOtherRestaurant} {
		w := f.request("POST", "/api/v2/r/"+tenant+"/feedback", body, nil)
		if w.Code != 409 {
			t.Fatalf("feedback retry=%d %s", w.Code, w.Body)
		}
	}
	if len(f.requests) != 3 || f.requests[0].Body != f.requests[1].Body || f.requests[1].Body == f.requests[2].Body || !strings.Contains(f.requests[2].Body, scopedOtherRestaurant) {
		t.Fatalf("retargeted namespace=%v", f.requests)
	}
}

func TestG2SummaryOpaqueIDsUseTupleOrder(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		kind := "stock"
		if strings.HasSuffix(r.URL.Path, "movements") {
			kind = "movements"
		}
		page := summaryPage(scopedRestaurant, kind, true)
		data, err := json.Marshal(page["items"])
		if err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		if err := json.Unmarshal(data, &rows); err != nil {
			t.Fatal(err)
		}
		first := rows[0]
		first["productID"] = "P"
		second := map[string]any{}
		for k, v := range first {
			second[k] = v
		}
		second["productID"] = "P\x00A"
		page["items"] = []any{first, second}
		writeScopedJSON(t, w, page)
	}
	w := f.request("GET", "/api/v2/orgs/"+scopedOrg+"/analytics/summary?restaurantID="+scopedRestaurant+"&expectedSettingsVersion=2", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"complete"`) {
		t.Fatalf("valid opaque IDs refused=%d %s", w.Code, w.Body)
	}
}
