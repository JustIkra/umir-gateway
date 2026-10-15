package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func finExample(t *testing.T, index int) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/fin1-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Examples []struct{ Value json.RawMessage }
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document.Examples[index].Value
}

func TestFINPlanningRouteAndStrictWireProfiles(t *testing.T) {
	c, err := contract()
	if err != nil {
		t.Fatal(err)
	}
	op, tenant := c.match("GET", "/api/v2/r/33333333-3333-4333-8333-333333333333/warehouse/supply-suggestions")
	if op == nil || op.id != "supplySuggestions" || op.Owner != "warehouse" || op.Capability != "stock.read" || tenant != "33333333-3333-4333-8333-333333333333" {
		t.Fatal("missing narrow supply route")
	}
	if err := ValidateScopeWire("ScopedSupplySuggestions", finExample(t, 0)); err != nil {
		t.Fatalf("valid supply including null no-history coverage: %v", err)
	}
	if err := ValidateScopeWire("ServingScopedRecommendations", finExample(t, 2)); err != nil {
		t.Fatalf("FIN1 recommendations: %v", err)
	}
	if route, _ := c.match("GET", "/api/v2/r/33333333-3333-4333-8333-333333333333/warehouse/recommendation-inputs"); route != nil {
		t.Fatal("private consumer facts became public")
	}
	if err := ValidateScopeWire("RegisterProductRequest", []byte(`{"commandID":"x","productID":"p","name":null,"baseUnit":"g"}`)); err == nil {
		t.Fatal("supply nullable field widened ordinary inputs")
	}
}

func TestFINPlanningRejectsCaptureDriftAndMalformedValues(t *testing.T) {
	c, err := contract()
	if err != nil {
		t.Fatal(err)
	}
	decision := AuthorizationResult{OrgID: "22222222-2222-4222-8222-222222222222", TenantID: "33333333-3333-4333-8333-333333333333", Settings: ScopeSettings{TimeZone: "Europe/Moscow", SettingsVersion: "1"}}
	for _, tc := range []struct {
		operation string
		index     int
	}{{"supplySuggestions", 0}, {"recommendations", 2}} {
		t.Run(tc.operation, func(t *testing.T) {
			op := c.Operations[tc.operation]
			if op == nil {
				t.Fatal("missing FIN1 operation")
			}
			original := finExample(t, tc.index)
			api := &ScopedAPI{}
			validate := func(body []byte) error {
				return api.validateResponse(op, BusinessResponse{Status: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, decision, "")
			}
			if err := validate(original); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"epoch", "version", "settings", "period", "coverage", "number"} {
				var doc struct {
					Context map[string]json.RawMessage
					Result  map[string]json.RawMessage
				}
				if err := json.Unmarshal(original, &doc); err != nil {
					t.Fatal(err)
				}
				switch field {
				case "epoch":
					doc.Result["coverage"] = json.RawMessage(`{"epoch":"88888888-8888-4888-8888-888888888888","coverageFrom":"2026-10-15T09:00:00+03:00","complete":false,"requestedFrom":"2026-10-08T12:00:00+03:00","availableFrom":"2026-10-15T09:00:00+03:00"}`)
				case "version":
					doc.Result["stateVersion"] = json.RawMessage(`"43"`)
				case "settings":
					doc.Context["settings"] = json.RawMessage(`{"timeZone":"Europe/Moscow","settingsVersion":"2"}`)
				case "period":
					doc.Result["window"] = json.RawMessage(`{"from":"2026-10-09T12:00:00+03:00","to":"2026-10-15T12:00:00+03:00","days":7}`)
				case "coverage":
					doc.Result["coverage"] = json.RawMessage(`{"epoch":"44444444-4444-4444-8444-444444444444","coverageFrom":"2026-10-15T09:00:00+03:00","complete":true,"requestedFrom":"2026-10-08T12:00:00+03:00","availableFrom":"2026-10-15T09:00:00+03:00"}`)
				case "number":
					doc.Result["stateVersion"] = json.RawMessage(`42`)
				}
				body, err := json.Marshal(map[string]any{"context": doc.Context, "result": doc.Result})
				if err != nil {
					t.Fatal(err)
				}
				if err := validate(body); err == nil {
					t.Fatalf("%s drift accepted", field)
				}
			}
		})
	}
}
