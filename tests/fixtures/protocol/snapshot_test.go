package protocol

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReviewedObservationSchemaSnapshot(t *testing.T) {
	if SHA(schemaJSON) != "3fd4016cfb395c80b9492727b4d60f12b370355f81fd3356abc84984035a044c" {
		t.Fatal("embedded schema differs from the reviewed observation correction")
	}
	if Protocol != "umir-operational-fixtures/1.1.0" {
		t.Fatal("snapshot refresh changed protocol version")
	}
}

func TestFeedbackPairSchemaDoesNotAddGatewayCapability(t *testing.T) {
	clock := testClock(t)
	handler, err := NewHandler(HandlerOptions{Project: testProject, Credential: strings.Repeat("a", 64), Clock: clock, Ticks: NewTicks(clock), BinarySHA256: strings.Repeat("0", 64), ConfigSHA256: strings.Repeat("1", 64), Ready: func(context.Context) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	app := `{"kind":"app","userID":"` + testID + `","orgID":"` + testID + `","tenantID":"` + testID + `"}`
	pair := `{"namespace":` + app + `,"submissionID":"` + testID + `"}`
	other := strings.Replace(pair, `"tenantID":"`+testID+`"`, `"tenantID":"22222222-2222-4222-8222-222222222222"`, 1)
	data := `{"submissions":[` + pair + `,` + other + `,{"namespace":{"kind":"anonymous"},"submissionID":"` + testID + `"}],"waitMs":0}`
	request := func(data string) []byte {
		return []byte(`{"version":1,"project":"` + testProject + `","requestID":"` + testID + `","operation":"feedback.observe","data":` + data + `}`)
	}
	if err := validate("feedback_observe_request", request(data)); err != nil {
		t.Fatal("reviewed three-namespace selector rejected", err)
	}
	for _, invalid := range []string{
		`{"submissionIDs":["` + testID + `"],"waitMs":0}`,
		`{"submissions":[` + pair + `,` + pair + `],"waitMs":0}`,
		strings.Replace(data, `"kind":"anonymous"`, `"kind":"anonymous","tenantID":"`+testID+`"`, 1),
	} {
		if err := validate("feedback_observe_request", request(invalid)); err == nil {
			t.Fatal("superseded or malformed observation selector admitted")
		}
	}
	r := httptest.NewRequest("POST", ControlPath, strings.NewReader(string(request(data))))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var response Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 404 || response.Error == nil || response.Error.Code != "UnsupportedOperation" || response.Error.Effect != "none" || response.Error.Retryable {
		t.Fatal("schema inventory enabled a Feedback operation on Gateway")
	}
	if len(handler.cache) != 0 || clock.Read().Generation != "1" || gatewayOperation("feedback.observe") {
		t.Fatal("unsupported observation affected Gateway controls")
	}
}
