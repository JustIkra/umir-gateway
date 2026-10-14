package catalog

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

type testClock struct{ state ClockState }

func (c *testClock) CatalogClock() ClockState { return c.state }
func TestCatalogBoundaryAndClockQualification(t *testing.T) {
	c := &testClock{ClockState{Instant: "2026-10-13T09:00:00+03:00", Generation: "1", InstanceID: "11111111-1111-4111-8111-111111111111", Source: "owner", Healthy: true}}
	calls := 0
	report := CatalogReport{Amendment: Amendment, Project: "umir-backend-0123456789abcdef01234567", InstanceID: c.state.InstanceID, Clock: c.state, BinarySHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), Catalog: Fact{Owner: "gateway", Version: "go1.26.9-embedded", ArchiveSHA256: strings.Repeat("c", 64), ArchiveBytes: 100, BuildToolchain: "go1.26.9", Ready: true, ProvenanceSHA256: strings.Repeat("d", 64)}}
	healthy := true
	handler, err := NewHandler(Options{Project: report.Project, Credential: strings.Repeat("e", 64), BinarySHA256: report.BinarySHA256, ConfigSHA256: report.ConfigSHA256, Clock: c, Ready: func(context.Context) bool { return healthy }, Observe: func(context.Context, Clock) (CatalogReport, error) { calls++; return report, nil }})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Amendment: Amendment, Project: report.Project, RequestID: c.state.InstanceID, ExpectedInstanceID: c.state.InstanceID, ExpectedGeneration: "1", Action: "catalog-report"}
	bytes, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	run := func(body string, auth bool, path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if auth {
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("e", 64))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := run(string(bytes), false, Path); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, body := range []string{string(bytes) + `{}`, strings.Replace(string(bytes), `"amendment"`, `"Amendment"`, 1), strings.Replace(string(bytes), `"action":`, `"action":"catalog-report","action":`, 1), strings.Replace(string(bytes), `"catalog-report"`, `"publish-next"`, 1), strings.TrimSuffix(string(bytes), "}") + `,"profile":"auth-rotation"}`} {
		if w := run(body, true, Path); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := run(string(bytes), true, Path+"?x=1"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	first := run(string(bytes), true, Path)
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	if w := run(string(bytes), true, Path); w.Code != 200 || w.Body.String() != first.Body.String() || calls != 1 {
		t.Fatal("replay not bounded cached read", calls)
	}
	request.ExpectedGeneration = "2"
	changed, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if w := run(string(changed), true, Path); w.Code != 409 {
		t.Fatal("changed ID not rejected", w.Code)
	}
	request.RequestID = "22222222-2222-4222-8222-222222222222"
	changed, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if w := run(string(changed), true, Path); w.Code != 409 {
		t.Fatal("stale clock admitted", w.Code)
	}
	request.ExpectedGeneration = "1"
	changed, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	healthy = false
	if w := run(string(changed), true, Path); w.Code != 503 {
		t.Fatal("unready owner admitted", w.Code)
	}
	if calls != 1 {
		t.Fatal("denial observed catalog", calls)
	}
}

func TestQualifiedClientCatalogShapeAndCorrelation(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	request := Request{Amendment: Amendment, Project: "umir-backend-0123456789abcdef01234567", RequestID: id, ExpectedInstanceID: id, ExpectedGeneration: "1", Action: "catalog-report"}
	report := CatalogReport{Amendment: Amendment, RequestID: id, Project: request.Project, InstanceID: id, Clock: ClockState{Instant: "2026-10-13T09:00:00+03:00", Generation: "1", InstanceID: id, Source: "owner", Healthy: true}, BinarySHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), Catalog: Fact{Owner: "gateway", Version: "go1.26.9-embedded", ArchiveSHA256: strings.Repeat("c", 64), ArchiveBytes: 400000, BuildToolchain: "go1.26.9", Ready: true, ProvenanceSHA256: strings.Repeat("d", 64)}}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReply(data, request, 200); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*CatalogReport){func(r *CatalogReport) { r.RequestID = "22222222-2222-4222-8222-222222222222" }, func(r *CatalogReport) { r.Project = "umir-backend-ffffffffffffffffffffffff" }, func(r *CatalogReport) { r.Clock.Generation = "2" }, func(r *CatalogReport) { r.Clock.Instant = "2026-10-13T06:00:00Z" }, func(r *CatalogReport) { r.Catalog.Version = "go1.26.9" }, func(r *CatalogReport) { r.Catalog.Ready = false }, func(r *CatalogReport) { r.Catalog.ArchiveBytes = 0 }} {
		copy := report
		mutation(&copy)
		body, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateReply(body, request, 200); err == nil {
			t.Fatal("mismatched catalog admitted")
		}
	}
	for _, body := range []string{strings.Replace(string(data), `"version":"go1.26.9-embedded"`, `"version":"go1.26.9-embedded","version":"go1.26.9-embedded"`, 1), strings.Replace(string(data), `"archiveBytes":400000`, `"ArchiveBytes":400000`, 1), string(data) + `{}`} {
		if err := ValidateReply([]byte(body), request, 200); err == nil {
			t.Fatal("invalid catalog structure admitted")
		}
	}
	failure, err := json.Marshal(ProfileError{Amendment: Amendment, RequestID: id, Error: "ProfileAdmissionFailed"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReply(failure, request, 503); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReply(failure, request, 200); err == nil {
		t.Fatal("refusal relabelled successful catalog")
	}
	if err := ValidateReply(failure, request, 403); err == nil {
		t.Fatal("incorrect refusal status accepted")
	}
}
