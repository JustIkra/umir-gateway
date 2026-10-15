package httpapi

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

func validatePlanningCapture(operation string, data []byte, settings ScopeSettings) error {
	var envelope struct {
		Context struct {
			RuntimeEpoch, WarehouseEpoch, StateVersion string
			EvaluatedAt                                time.Time
			Settings                                   ScopeSettings
		}
		Result struct {
			EvaluatedAt  time.Time
			StateVersion string
			Window       struct {
				From, To time.Time
				Days     int
			}
			Coverage struct {
				Epoch                                      string
				CoverageFrom, RequestedFrom, AvailableFrom time.Time
				Complete                                   bool
			}
			Items []struct {
				ProductID, DishID string
				PriorityExpiresAt time.Time
				Reasons           json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	c, v := envelope.Context, envelope.Result
	invalid := errors.New("inconsistent FIN1 capture")
	from := c.EvaluatedAt.Add(-168 * time.Hour)
	if c.Settings != settings || !v.EvaluatedAt.Equal(c.EvaluatedAt) || v.StateVersion != c.StateVersion || v.Window.Days != 7 || !v.Window.From.Equal(from) || !v.Window.To.Equal(c.EvaluatedAt) {
		return invalid
	}
	epoch := c.RuntimeEpoch
	if operation == "recommendations" {
		epoch = c.WarehouseEpoch
	}
	coverage := v.Coverage
	available := from
	if coverage.CoverageFrom.After(from) {
		available = coverage.CoverageFrom
	}
	if coverage.Epoch != epoch || coverage.CoverageFrom.After(c.EvaluatedAt) || coverage.Complete != !from.Before(coverage.CoverageFrom) || !coverage.RequestedFrom.Equal(from) || !coverage.AvailableFrom.Equal(available) {
		return invalid
	}
	seen := map[string]bool{}
	previous := ""
	for _, item := range v.Items {
		if operation == "supplySuggestions" {
			if seen[item.ProductID] || (previous != "" && item.ProductID < previous) {
				return invalid
			}
			seen[item.ProductID] = true
			previous = item.ProductID
			continue
		}
		if seen[item.DishID] {
			return invalid
		}
		seen[item.DishID] = true
		products := map[string]bool{}
		var earliest time.Time
		var reasons []struct {
			ProductID, RemainingSeconds string
			ExpiresAt                   time.Time
		}
		if err := json.Unmarshal(item.Reasons, &reasons); err != nil {
			return err
		}
		for _, reason := range reasons {
			seconds, err := strconv.ParseInt(reason.RemainingSeconds, 10, 64)
			if err != nil || products[reason.ProductID] || !reason.ExpiresAt.After(c.EvaluatedAt) || reason.ExpiresAt.After(c.EvaluatedAt.Add(72*time.Hour)) || seconds != int64(reason.ExpiresAt.Sub(c.EvaluatedAt)/time.Second) {
				return invalid
			}
			products[reason.ProductID] = true
			if earliest.IsZero() || reason.ExpiresAt.Before(earliest) {
				earliest = reason.ExpiresAt
			}
		}
		if !item.PriorityExpiresAt.Equal(earliest) {
			return invalid
		}
	}
	return nil
}
