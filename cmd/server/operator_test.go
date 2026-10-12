package main

import (
	"path/filepath"
	"testing"
)

// testOrigin is the frontend origin the tests configure and send.
const testOrigin = "http://127.0.0.1:8080"

// operatorEnv returns the operator settings for one test, with its own account directory.
func operatorEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"OPERATOR_COOKIE_MODE":   "loopback-development",
		"OPERATOR_PUBLIC_ORIGIN": testOrigin,
		"OPERATOR_STORE_PATH":    filepath.Join(t.TempDir(), "account.json"),
	}
}
