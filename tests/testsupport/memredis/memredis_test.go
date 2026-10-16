package memredis

import (
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/admission"
	"github.com/JustIkra/umir-gateway/internal/admission/contract"
)

func env(s *Store) contract.Env { return contract.Env{Advance: s.Advance} }

func newStore() *Store { return New(time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)) }

func TestContractLimiter(t *testing.T) {
	contract.Limiter(t, func(t *testing.T) (admission.Limiter, contract.Env) {
		s := newStore()
		return s.Limiter(), env(s)
	})
}

func TestContractSlots(t *testing.T) {
	contract.Slots(t, func(t *testing.T) (admission.Slots, contract.Env) {
		s := newStore()
		return s.Slots(), env(s)
	})
}

func TestContractLeader(t *testing.T) {
	contract.Leader(t, func(t *testing.T) (admission.Leader, contract.Env) {
		s := newStore()
		return s.Leader(), env(s)
	})
}
