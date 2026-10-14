package httpapi

import (
	"encoding/json"
	"errors"
)

func validateProductBatchRelations(body []byte, productID string, settings ScopeSettings) error {
	var result struct {
		Context struct {
			TenantID, RuntimeEpoch, StateVersion, EvaluatedAt string
			Settings                                          ScopeSettings
		}
		Result struct {
			ProductID, EvaluatedAt string
			Page                   struct {
				TenantID, Epoch, StateVersion, PrefixSequence string
				Settings                                      ScopeSettings
			}
			Items []struct {
				Batch struct{ ProductID string }
			}
		}
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	context, page := result.Context, result.Result.Page
	if result.Result.ProductID != productID || result.Result.EvaluatedAt != context.EvaluatedAt || page.TenantID != context.TenantID || page.Epoch != context.RuntimeEpoch || page.StateVersion != context.StateVersion || page.PrefixSequence != context.StateVersion || page.Settings != context.Settings || context.Settings != settings {
		return errors.New("product batch capture identity mismatch")
	}
	for _, item := range result.Result.Items {
		if item.Batch.ProductID != productID {
			return errors.New("product batch row identity mismatch")
		}
	}
	return nil
}
