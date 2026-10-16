package operatorhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/JustIkra/umir-gateway/internal/admission"
)

func (a *RemoteAPI) admitFacade(w http.ResponseWriter, r *http.Request, op *FacadeOperation, browser BrowserContext, body []byte) bool {
	if a.admission == nil {
		return true
	}
	var rule admission.Rule
	var subjects admission.Subjects
	var input struct {
		Purpose   string `json:"purpose"`
		CommandID string `json:"commandID"`
	}
	_ = json.Unmarshal(body, &input)
	client := ""
	if a.clients != nil {
		client = a.clients.Client(r)
	}
	switch op.id {
	case "csrf":
		rule, subjects = admission.RuleCSRF, admission.Subjects{Client: client, Global: browser.SessionToken == "" && browser.PreauthToken == ""}
	case "login":
		rule, subjects = admission.RuleLogin, admission.Subjects{Client: client}
	case "beginEmailChallenge":
		switch input.Purpose {
		case "registration":
			if browser.SessionToken != "" {
				return true
			}
			rule = admission.RuleRegistration
			subjects = admission.Subjects{Client: client, Preauth: browser.PreauthToken, Global: true}
		case "password_reset":
			rule, subjects = admission.RuleReset, admission.Subjects{Client: client}
		default:
			return true
		}
	default:
		return true
	}
	attemptID := ""
	if rule == admission.RuleRegistration || rule == admission.RuleReset {
		attemptID = input.CommandID
	}
	verdict, err := a.admission.Admit(r.Context(), rule, subjects, admission.Attempt{ID: attemptID, Fingerprint: string(body)})
	if err != nil {
		status, code, outcome := http.StatusServiceUnavailable, "ServiceUnavailable", "not_committed"
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			outcome = "unavailable"
		}
		if errors.Is(err, admission.ErrConflict) {
			status, code = http.StatusConflict, "CommandConflict"
			outcome = "not_committed"
		}
		a.writeAdmissionFailure(w, r, status, code, outcome, 0)
		return false
	}
	if !verdict.Allowed {
		a.writeAdmissionFailure(w, r, http.StatusTooManyRequests, "RateLimited", "not_committed", admission.RetryAfterSeconds(verdict.RetryAfter))
		return false
	}
	return true
}

func (a *RemoteAPI) writeAdmissionFailure(w http.ResponseWriter, r *http.Request, status int, code, outcome string, retryAfter int) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	details := map[string]any(nil)
	if retryAfter > 0 {
		details = map[string]any{"retryAfterSeconds": retryAfter}
	}
	if err := json.NewEncoder(w).Encode(struct {
		Code      string         `json:"code"`
		Outcome   string         `json:"outcome"`
		Message   string         `json:"message"`
		Retryable bool           `json:"retryable"`
		Details   map[string]any `json:"details,omitempty"`
	}{code, outcome, "request admission refused", retryAfter > 0, details}); err != nil {
		a.boundary.logger.Printf("operator admission response failed")
	}
}

func (a *RemoteAPI) admitCSRFGlobal(w http.ResponseWriter, r *http.Request) bool {
	if a.admission == nil {
		return true
	}
	verdict, err := a.admission.Admit(r.Context(), admission.RuleCSRF, admission.Subjects{Global: true}, admission.Attempt{})
	if err != nil {
		a.writeAdmissionFailure(w, r, http.StatusServiceUnavailable, "ServiceUnavailable", "unavailable", 0)
		return false
	}
	if !verdict.Allowed {
		a.writeAdmissionFailure(w, r, http.StatusTooManyRequests, "RateLimited", "not_committed", admission.RetryAfterSeconds(verdict.RetryAfter))
		return false
	}
	return true
}
