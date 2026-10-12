package operatorhttp

import (
	"net/http"
	"testing"
)

// TestAccountBodiesNeedExactUniqueKeys pins the exact JSON fields of the account routes: encoding/json
// alone would match keys case-insensitively, keep the last of duplicate keys and read null as false.
func TestAccountBodiesNeedExactUniqueKeys(t *testing.T) {
	f := loopbackFixture(t)
	for name, body := range map[string]string{
		"null rememberMe":        `{"login":"operator","password":"` + testPassword + `","rememberMe":null}`,
		"case-variant key":       `{"login":"operator","password":"` + testPassword + `","RememberMe":true}`,
		"duplicate key":          `{"login":"operator","password":"wrong password","password":"` + testPassword + `"}`,
		"case-variant duplicate": `{"login":"operator","password":"wrong password","PASSWORD":"` + testPassword + `"}`,
	} {
		t.Run("sign-in "+name, func(t *testing.T) {
			preauth, token := f.anonymous()
			w := f.do(call{method: http.MethodPost, path: "/api/operator/session", body: body,
				cookies: []*http.Cookie{preauth}, csrf: token, origin: testOrigin})
			wantProblem(t, w, http.StatusBadRequest, "InvalidRequest")
		})
	}
	session, token := f.login()
	for name, tc := range map[string]struct{ path, body string }{
		"display name case-variant key": {"/api/operator/me/display-name", `{"DisplayName":"Смена"}`},
		"display name duplicate key":    {"/api/operator/me/display-name", `{"displayName":"Смена","displayName":"Другое"}`},
		"display name null":             {"/api/operator/me/display-name", `{"displayName":null}`},
		"password duplicate key": {"/api/operator/me/password",
			`{"currentPassword":"` + testPassword + `","newPassword":"first new password","newPassword":"second new password"}`},
	} {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, f.patch(tc.path, tc.body, session, token), http.StatusBadRequest, "InvalidRequest")
		})
	}
	if commits := f.store.commits(); len(commits) != 0 {
		t.Errorf("rejected bodies changed the account: %+v", commits)
	}
}
