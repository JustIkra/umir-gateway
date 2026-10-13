package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func summaryPage(tenant, kind string, second bool) map[string]any {
	settings := map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "2"}
	context := map[string]any{"orgID": scopedOrg, "tenantID": tenant, "runtimeEpoch": scopedEpoch, "settings": settings, "evaluatedAt": "2026-10-13T01:00:00+03:00", "stateVersion": "4"}
	page := map[string]any{"tenantID": tenant, "epoch": scopedEpoch, "stateVersion": "4", "prefixSequence": "9", "filterFingerprint": strings.Repeat("a", 64), "settings": settings}
	items := []any{}
	count := 500
	start := 0
	if second {
		count = 1
		start = 500
	}
	for i := start; i < start+count; i++ {
		row := map[string]any{"productID": fmt.Sprintf("P%04d", i), "name": "Exact", "baseUnit": "g"}
		if kind == "stock" {
			row["availableQuantity"] = "9007199254740993"
			row["pendingWriteoffQuantity"] = "0"
			row["onHandQuantity"] = "9007199254740993"
			row["expiringQuantity"] = "0"
		} else {
			row["receivedQuantity"] = "9007199254740993"
			row["orderedQuantity"] = "0"
			row["writtenOffQuantity"] = "0"
		}
		items = append(items, row)
	}
	result := map[string]any{"context": context, "page": page, "items": items}
	if kind == "stock" {
		result["riskHours"] = 48
		result["riskCutoff"] = "2026-10-15T01:00:00+03:00"
	} else {
		result["from"] = "2026-10-07T00:00:00+03:00"
		result["to"] = "2026-10-14T00:00:00+03:00"
		result["coverage"] = map[string]any{"epoch": scopedEpoch, "coverageFrom": "2026-10-07T00:00:00+03:00", "complete": true, "requestedFrom": "2026-10-07T00:00:00+03:00", "availableFrom": "2026-10-07T00:00:00+03:00"}
	}
	if !second {
		result["nextCursor"] = kind + "-next"
	}
	return result
}

func TestG2SummaryCollectsEveryPageAndKeepsUnavailableExplicit(t *testing.T) {
	f := newScopedFixture(t)
	f.peer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tenant := scopedRestaurant
		if strings.Contains(r.URL.Path, scopedOtherRestaurant) {
			w.WriteHeader(503)
			writeScopedJSON(t, w, map[string]any{"code": "UpstreamUnavailable", "outcome": "unavailable", "message": "missing", "retryable": false})
			return
		}
		kind := "stock"
		if strings.HasSuffix(r.URL.Path, "movements") {
			kind = "movements"
		}
		writeScopedJSON(t, w, summaryPage(tenant, kind, r.URL.Query().Get("cursor") != ""))
	}
	w := f.request("GET", "/api/v2/orgs/"+scopedOrg+"/analytics/summary?restaurantID="+scopedRestaurant+"&restaurantID="+scopedOtherRestaurant+"&expectedSettingsVersion=2", "", nil)
	var result struct {
		Status      string
		Restaurants []struct {
			RestaurantID, Status string
			Stock, Movements     json.RawMessage
			Error                json.RawMessage
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("summary=%d %s", w.Code, w.Body)
	}
	if w.Code != 200 || result.Status != "partial" || len(result.Restaurants) != 2 {
		t.Fatalf("summary=%d %s", w.Code, w.Body)
	}
	for _, report := range []json.RawMessage{result.Restaurants[0].Stock, result.Restaurants[0].Movements} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(report, &fields); err != nil {
			t.Fatal(err)
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(fields["items"], &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 501 || fields["nextCursor"] != nil || !strings.Contains(string(rows[0]), "9007199254740993") {
			t.Fatalf("truncated/inexact report: rows=%d", len(rows))
		}
	}
	if result.Restaurants[1].Status != "unavailable" || len(result.Restaurants[1].Stock) != 0 || len(result.Restaurants[1].Error) == 0 {
		t.Fatalf("unavailable became success=%+v", result.Restaurants[1])
	}
}

func TestG2SummaryFailsWholeCrossOrgBeforeBusinessDispatch(t *testing.T) {
	f := newScopedFixture(t)
	w := f.request("GET", "/api/v2/orgs/88888888-8888-4888-8888-888888888888/analytics/summary?restaurantID="+scopedRestaurant+"&expectedSettingsVersion=2", "", nil)
	if w.Code != 403 || len(f.requests) != 0 {
		t.Fatalf("cross org=%d dispatch=%d", w.Code, len(f.requests))
	}
}

func TestG2SummaryRejectsPagingDriftAndCycles(t *testing.T) {
	for _, mode := range []string{"drift", "cycle", "duplicate", "tenant"} {
		t.Run(mode, func(t *testing.T) {
			f := newScopedFixture(t)
			f.peer = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				second := r.URL.Query().Get("cursor") != ""
				page := summaryPage(scopedRestaurant, "stock", second)
				if second {
					switch mode {
					case "drift":
						page["riskCutoff"] = "2026-10-16T01:00:00+03:00"
					case "cycle":
						page["nextCursor"] = "stock-next"
					case "duplicate":
						page["items"] = summaryPage(scopedRestaurant, "stock", false)["items"]
					case "tenant":
						page["context"] = summaryPage(scopedOtherRestaurant, "stock", false)["context"]
					}
				}
				writeScopedJSON(t, w, page)
			}
			w := f.request("GET", "/api/v2/orgs/"+scopedOrg+"/analytics/summary?restaurantID="+scopedRestaurant+"&expectedSettingsVersion=2", "", nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"unavailable"`) || strings.Contains(w.Body.String(), `"stock":`) {
				t.Fatalf("bad report accepted=%d %s", w.Code, w.Body)
			}
		})
	}
}
