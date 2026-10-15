package operatorhttp

import (
	"strings"
	"testing"
)

func TestRegistrationFacadeStrictInputs(t *testing.T) {
	begin := FacadeRequest{Method: "POST", Path: "/api/v2/email-challenges", Body: []byte(`{"commandID":"register-begin","email":"new@umir.invalid","purpose":"registration"}`)}
	op, err := ValidateFacadeRequest(begin)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.ValidateResponse(begin, []byte(`{"challengeID":"00000000-0000-4000-8000-000000000001","expiresAt":"2026-10-15T18:10:00+03:00","resendAvailableAt":"2026-10-15T18:01:00+03:00","state":"pending"}`)); err != nil {
		t.Fatal(err)
	}
	body := `{"commandID":"register-complete","challengeID":"00000000-0000-4000-8000-000000000001","proof":"01234567890123456789012345678901","purpose":"registration","displayName":"New User","password":"valid-password","rememberMe":true}`
	complete := FacadeRequest{Method: "POST", Path: "/api/v2/email-challenges/00000000-0000-4000-8000-000000000001/complete", Body: []byte(body)}
	if _, err := ValidateFacadeRequest(complete); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(body, `"password":"valid-password"`, `"password":"short"`, 1),
		strings.Replace(body, `"password":"valid-password"`, `"password":null`, 1),
		strings.Replace(body, `"purpose":"registration"`, `"purpose":"foo"`, 1),
		strings.Replace(body, `"purpose":"registration"`, `"purpose":"password_reset"`, 1),
		strings.Replace(body, `"commandID":"register-complete"`, `"commandID":"`+strings.Repeat("x", 257)+`"`, 1),
		strings.Replace(body, `"purpose":"registration"`, `"purpose":"registration","purpose":"registration"`, 1),
		strings.Replace(body, `"displayName":"New User"`, `"displayName":"x"`, 1),
		strings.Replace(body, `"rememberMe":true`, `"rememberMe":true,"newPassword":"forbidden-password"`, 1),
		strings.Replace(body, `"rememberMe":true`, `"rememberMe":true,"newPassword":""`, 1),
		strings.Replace(body, `"purpose":"registration"`, `"purpose":"login"`, 1),
		strings.Replace(body, `"challengeID":"00000000-0000-4000-8000-000000000001"`, `"challengeID":"00000000-0000-4000-8000-000000000099"`, 1),
	} {
		complete.Body = []byte(bad)
		if _, err := ValidateFacadeRequest(complete); err == nil {
			t.Fatal("malformed registration accepted")
		}
	}
}

func TestRegistrationBeginRejectsUnknownPurposeAndLongCommand(t *testing.T) {
	for _, body := range []string{`{"commandID":"begin","email":"a@umir.invalid","purpose":"foo"}`, `{"commandID":"begin","email":"a@umir.invalid","purpose":"registration","purpose":"registration"}`, `{"commandID":"` + strings.Repeat("x", 257) + `","email":"a@umir.invalid","purpose":"registration"}`} {
		if _, err := ValidateFacadeRequest(FacadeRequest{Method: "POST", Path: "/api/v2/email-challenges", Body: []byte(body)}); err == nil {
			t.Fatal("invalid begin admitted")
		}
	}
}
