package main

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"testing"
)

func TestFINPlanningProxyPreservesValuesAndRechecksAuthority(t *testing.T) {
	data, err := os.ReadFile("../../internal/httpapi/testdata/fin1-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples struct {
		Examples []struct{ Value map[string]json.RawMessage }
	}
	if err := json.Unmarshal(data, &examples); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		index                           int
		operation, service, suffix, key string
		audiences                       []string
	}{{0, "supplySuggestions", "warehouse", "supply-suggestions", "warehouse-key", []string{"umir-warehouse"}}, {2, "recommendations", "serving", "recommendations", "serving-key", []string{"umir-serving", "umir-warehouse"}}} {
		t.Run(tc.operation, func(t *testing.T) {
			f := newScopedFixture(t)
			if w := f.request("GET", "/api/v2/r/"+scopedRestaurant+"/warehouse/recommendation-inputs", "", nil); w.Code == 200 || len(f.requests) != 0 || len(f.authorizations) != 0 {
				t.Fatal("private recommendation facts reached a public dispatch")
			}
			value := examples.Examples[tc.index].Value
			var context map[string]json.RawMessage
			if err := json.Unmarshal(value["context"], &context); err != nil {
				t.Fatal(err)
			}
			context["settings"] = json.RawMessage(`{"timeZone":"Europe/Moscow","settingsVersion":"2"}`)
			value["context"], err = json.Marshal(context)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			f.peer = func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/internal/"+tc.service+"/v2/r/"+scopedRestaurant+"/"+tc.suffix || r.Header.Get("X-Umir-Service-Key") != tc.key || r.Header.Get("Authorization") != "Bearer auth-issued-token" || r.Header.Get("Cookie") != "" {
					t.Error("incorrect FIN1 private dispatch")
				}
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write(body); err != nil {
					t.Error(err)
				}
			}
			path := "/api/v2/r/" + scopedRestaurant + "/" + tc.service + "/" + tc.suffix
			w := f.request("GET", path, "", map[string]string{"X-Umir-Activity": "background"})
			if w.Code != 200 || w.Body.String() != string(body) || len(f.requests) != 1 || len(f.authorizations) != 1 {
				t.Fatalf("FIN1 values/dispatch: %d %s", w.Code, w.Body)
			}
			var request struct {
				Operation, Activity string
				Audiences           []string
			}
			encoded, err := json.Marshal(f.authorizations[0])
			if err != nil {
				t.Fatal(err)
			}
			if json.Unmarshal(encoded, &request) != nil || request.Operation != tc.operation || request.Activity != "background" || !slices.Equal(request.Audiences, tc.audiences) {
				t.Fatalf("wrong FIN1 audience/operation: %+v", request)
			}
			f.mu.Lock()
			f.deny = true
			f.mu.Unlock()
			w = f.request("GET", path, "", nil)
			if w.Code != 403 || len(f.requests) != 1 || len(f.authorizations) != 2 {
				t.Fatalf("revoked access dispatched: %d", w.Code)
			}
		})
	}
}
