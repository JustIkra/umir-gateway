package authclient

import "testing"

func TestUA1CollectionFailures(t *testing.T) {
	for _, tc := range []struct {
		code    string
		status  int
		details string
	}{
		{"RefreshRequired", 409, `,"details":{"refreshRequired":true}`},
		{"LimitExceeded", 503, ""},
		{"ScopeDeleted", 410, ""},
	} {
		data := []byte(`{"code":"` + tc.code + `","outcome":"unavailable","message":"Collection could not be read","retryable":false` + tc.details + `}`)
		failure, err := decodeCollectionFailure(data, tc.status)
		if err != nil || failure.Status != tc.status || failure.Code != tc.code {
			t.Fatalf("collection failure %s lost: %v", tc.code, err)
		}
		if ordinary, err := decodeFacadeFailure(data, tc.status); err == nil || ordinary != nil {
			t.Fatalf("collection failure %s accepted by ordinary command", tc.code)
		}
		if wrongStatus, err := decodeCollectionFailure(data, 400); err == nil || wrongStatus != nil {
			t.Fatalf("wrong status accepted for %s", tc.code)
		}
	}
}
