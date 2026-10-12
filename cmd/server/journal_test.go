package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/journal"
)

func TestAdmittedWritesReachTheJournal(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }))
	t.Cleanup(upstream.Close)
	values := operatorEnv(t)
	values["SERVING_URL"], values["WAREHOUSE_URL"] = upstream.URL, upstream.URL
	app := assemble(t, values)
	signedIn := withSession(app.handler, signIn(t, app.handler))
	signedIn.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/warehouse/deliveries?draft=1", strings.NewReader("{}")))
	signedIn.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/warehouse/inventory", nil))
	app.handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/serving/orders", nil))

	entries := app.journal.Entries(0)
	if len(entries) != 1 || entries[0].Source != journal.SourceRequest || entries[0].Method != http.MethodPost ||
		entries[0].Path != "/api/warehouse/deliveries" || entries[0].Status != http.StatusCreated || entries[0].Outcome != journal.OutcomeSuccess {
		t.Fatalf("entries: %+v", entries)
	}
}
