package main

import (
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/admission"
	"github.com/JustIkra/umir-gateway/internal/bootstrap"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/tests/testsupport/memredis"
)

func testAdmission(t *testing.T, cfg config.Config) bootstrap.AdmissionPorts {
	t.Helper()
	store := memredis.New(time.Now())
	budgets := make(map[string]admission.Budget, len(cfg.Budgets))
	for name, budget := range cfg.Budgets {
		budgets[name] = admission.Budget{Limit: budget.Limit, Window: budget.Window, Strict: budget.Strict}
	}
	service, err := admission.New(admission.Options{Limiter: store.Limiter(), Continuity: store.Continuity(), Budgets: budgets, Key: []byte("gateway-test-admission-key-0123456789")})
	if err != nil {
		t.Fatal(err)
	}
	ports := bootstrap.AdaptAdmission(service, store.Slots())
	ports.CursorKey = []byte("gateway-test-live-cursor-key-0123456789")
	return ports
}
