package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
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

// w1Tenant builds a valid restaurant identity; the Auth fixture authorizes any restaurant it is asked about.
func w1Tenant(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1) }

func w1SummaryURL(n int) string {
	query := "expectedSettingsVersion=2"
	for i := range n {
		query += "&restaurantID=" + w1Tenant(i)
	}
	return "/api/v2/orgs/" + scopedOrg + "/analytics/summary?" + query
}

// w1SummaryPeer answers every report for the restaurant in the path; hook runs first and may block.
func w1SummaryPeer(t *testing.T, hook func(tenant string, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/internal/warehouse/v2/r/"
		tenant := strings.SplitN(strings.TrimPrefix(r.URL.Path, prefix), "/", 2)[0]
		if hook != nil {
			hook(tenant, r)
		}
		kind := "stock"
		if strings.HasSuffix(r.URL.Path, "movements") {
			kind = "movements"
		}
		w.Header().Set("Content-Type", "application/json")
		writeScopedJSON(t, w, summaryPage(tenant, kind, r.URL.Query().Get("cursor") != ""))
	}
}

type w1Summary struct {
	Status      string
	EvaluatedAt string
	Restaurants []struct {
		RestaurantID, Status string
		Error                *struct{ Code, Outcome string }
	}
}

func w1DecodeSummary(t *testing.T, body string) w1Summary {
	t.Helper()
	var result w1Summary
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("summary body: %v: %s", err, body)
	}
	return result
}

func TestW1SummaryRespectsOverallDeadlineAndKeepsOrder(t *testing.T) {
	f := newScopedFixtureWith(t, map[string]string{"GATEWAY_SUMMARY_DEADLINE": "3s", "GATEWAY_SUMMARY_CONCURRENCY": "6"})
	slow := map[string]bool{w1Tenant(1): true, w1Tenant(4): true}
	f.peer = w1SummaryPeer(t, func(tenant string, r *http.Request) {
		if slow[tenant] {
			<-r.Context().Done() // an owner that never answers; released when the Gateway gives up
		}
	})
	started := time.Now()
	w := f.request("GET", w1SummaryURL(6), "", nil)
	if elapsed := time.Since(started); elapsed > 6*time.Second {
		t.Fatalf("summary took %s past a 3 s deadline", elapsed)
	}
	result := w1DecodeSummary(t, w.Body.String())
	if w.Code != 200 || result.Status != "partial" || len(result.Restaurants) != 6 {
		t.Fatalf("summary=%d %s", w.Code, w.Body)
	}
	for i, item := range result.Restaurants {
		want := "ok"
		if slow[w1Tenant(i)] {
			want = "unavailable"
		}
		if item.RestaurantID != w1Tenant(i) || item.Status != want {
			t.Fatalf("restaurant %d: %+v, want %s in request order", i, item, want)
		}
		if want == "unavailable" && (item.Error == nil || item.Error.Code != "UpstreamUnavailable" || item.Error.Outcome != "unavailable") {
			t.Fatalf("restaurant %d error: %+v", i, item.Error)
		}
	}
}

func TestW1SummaryBoundsConcurrentOwnerCalls(t *testing.T) {
	f := newScopedFixtureWith(t, map[string]string{"GATEWAY_SUMMARY_CONCURRENCY": "2"})
	var mu sync.Mutex
	active, peak := map[string]bool{}, 0
	f.peer = w1SummaryPeer(t, func(tenant string, _ *http.Request) {
		mu.Lock()
		active[tenant] = true
		peak = max(peak, len(active))
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
		mu.Lock()
		delete(active, tenant)
		mu.Unlock()
	})
	w := f.request("GET", w1SummaryURL(8), "", nil)
	if result := w1DecodeSummary(t, w.Body.String()); w.Code != 200 || result.Status != "complete" {
		t.Fatalf("summary=%d %s", w.Code, w.Body)
	}
	if peak < 2 || peak > 2 {
		t.Fatalf("restaurants served at once: %d, want exactly the bound of 2 reached", peak)
	}
}

func TestW1SummaryByteBudgetMarksRemainingUnavailable(t *testing.T) {
	f := newScopedFixtureWith(t, map[string]string{"GATEWAY_SUMMARY_MAX_BYTES": "1048576", "GATEWAY_SUMMARY_CONCURRENCY": "1"})
	f.peer = w1SummaryPeer(t, nil)
	w := f.request("GET", w1SummaryURL(12), "", nil)
	result := w1DecodeSummary(t, w.Body.String())
	if w.Code != 200 || result.Status != "partial" || len(result.Restaurants) != 12 {
		t.Fatalf("summary=%d %.300s", w.Code, w.Body)
	}
	ok := 0
	for i, item := range result.Restaurants {
		if item.RestaurantID != w1Tenant(i) {
			t.Fatalf("order lost at %d", i)
		}
		switch item.Status {
		case "ok":
			if ok != i {
				t.Fatalf("restaurant %d served after one was cut", i)
			}
			ok++
		case "unavailable":
			if item.Error == nil || item.Error.Code != "UpstreamUnavailable" || item.Error.Outcome != "unavailable" {
				t.Fatalf("restaurant %d error: %+v", i, item.Error)
			}
		default:
			t.Fatalf("restaurant %d status %q", i, item.Status)
		}
	}
	if ok == 0 || ok == 12 {
		t.Fatalf("%d restaurants fit a 1 MiB budget, want some but not all", ok)
	}
	if w.Body.Len() > 2<<20 {
		t.Fatalf("response of %d bytes exceeds the budget", w.Body.Len())
	}
}

func TestW1SummaryMatchesOrgSummarySchemaAndMoscowInstant(t *testing.T) {
	// The process zone must not leak into the instant.
	local := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = local })
	f := newScopedFixture(t)
	f.peer = w1SummaryPeer(t, nil)
	w := f.request("GET", w1SummaryURL(2), "", nil)
	if w.Code != 200 {
		t.Fatalf("summary=%d %s", w.Code, w.Body)
	}
	if err := httpapi.ValidateScopeWire("OrgSummary", w.Body.Bytes()); err != nil {
		t.Fatalf("response does not match OrgSummary: %v", err)
	}
	result := w1DecodeSummary(t, w.Body.String())
	if !strings.HasSuffix(result.EvaluatedAt, "+03:00") {
		t.Fatalf("evaluatedAt %q is not in Europe/Moscow", result.EvaluatedAt)
	}
}
