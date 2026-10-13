package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestG3AuthenticatedWriteRetainsBoundedPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()
	values := operatorEnv(t)
	values["SERVING_URL"], values["WAREHOUSE_URL"] = upstream.URL, upstream.URL
	app := assemble(t, values)
	creds := signIn(t, app.handler)
	server := httptest.NewServer(withSession(app.handler, creds))
	defer server.Close()

	path := "/api/warehouse/" + strings.Repeat("a", 1_000_000)
	request, err := http.NewRequest(http.MethodPost, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want admitted upstream 404", response.StatusCode)
	}
	entries := app.journal.Entries(0)
	if len(entries) != 1 {
		t.Fatalf("journal entries = %d", len(entries))
	}
	if entries[0].Status != http.StatusNotFound || len(entries[0].Path) > 1024 || !strings.HasPrefix(path, entries[0].Path) {
		t.Fatalf("journal status=%d path length=%d", entries[0].Status, len(entries[0].Path))
	}
	t.Logf("gateway accepted POST path length %d and retained it with upstream status %d", len(entries[0].Path), entries[0].Status)
}
