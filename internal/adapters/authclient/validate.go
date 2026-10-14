package authclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
	"github.com/JustIkra/umir-gateway/internal/strictjson"
)

var errInvalidResult = errors.New("invalid Auth result")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var emailPattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
var instantPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`)

func object(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	if strictjson.CheckText(data) != nil {
		return nil, errInvalidResult
	}
	fields, err := strictjson.Object(data)
	if err != nil {
		return nil, errInvalidResult
	}
	for key, value := range fields {
		if (!slices.Contains(required, key) && !slices.Contains(optional, key)) || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errInvalidResult
		}
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, errInvalidResult
		}
	}
	return fields, nil
}

func text(data json.RawMessage) (string, error) {
	var value string
	if json.Unmarshal(data, &value) != nil || value == "" {
		return "", errInvalidResult
	}
	return value, nil
}

func instant(data json.RawMessage) (time.Time, error) {
	value, err := text(data)
	if err != nil {
		return time.Time{}, err
	}
	if !instantPattern.MatchString(value) {
		return time.Time{}, errInvalidResult
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, errInvalidResult
	}
	return parsed, nil
}

func version(data json.RawMessage) bool {
	value, err := text(data)
	number, parseErr := strconv.ParseInt(value, 10, 64)
	return err == nil && parseErr == nil && number > 0 && strconv.FormatInt(number, 10) == value
}

func validateUser(data []byte) error {
	f, err := object(data, []string{"userID", "login", "displayName", "credentialVersion"}, []string{"email"})
	if err != nil {
		return err
	}
	id, err := text(f["userID"])
	if err != nil || !uuid.MatchString(id) || !version(f["credentialVersion"]) {
		return errInvalidResult
	}
	login, loginErr := text(f["login"])
	name, nameErr := text(f["displayName"])
	if loginErr != nil || nameErr != nil || utf8.RuneCountInString(login) > 128 || utf8.RuneCountInString(name) < 2 || utf8.RuneCountInString(name) > 80 {
		return errInvalidResult
	}
	if email, ok := f["email"]; ok {
		value, err := text(email)
		if err != nil || utf8.RuneCountInString(value) > 254 || !emailPattern.MatchString(value) {
			return errInvalidResult
		}
	}
	return nil
}

func validateSession(data []byte) error {
	f, err := object(data, []string{"expiresAt", "idleExpiresAt", "absoluteExpiresAt", "rememberMe", "csrfToken"}, nil)
	if err != nil {
		return err
	}
	expires, e1 := instant(f["expiresAt"])
	idle, e2 := instant(f["idleExpiresAt"])
	absolute, e3 := instant(f["absoluteExpiresAt"])
	var remember bool
	if e1 != nil || e2 != nil || e3 != nil || json.Unmarshal(f["rememberMe"], &remember) != nil || !expires.Equal(idle) || idle.After(absolute) || (remember && !idle.Equal(absolute)) {
		return errInvalidResult
	}
	_, err = text(f["csrfToken"])
	return err
}

func validateView(data []byte) error {
	f, err := object(data, []string{"user", "session"}, nil)
	if err != nil {
		return err
	}
	return errors.Join(validateUser(f["user"]), validateSession(f["session"]))
}

func validateIssued(data []byte) error {
	f, err := object(data, []string{"view", "sessionToken"}, nil)
	if err != nil {
		return err
	}
	token, err := text(f["sessionToken"])
	if err != nil || !cookieToken(token) {
		return errInvalidResult
	}
	return validateView(f["view"])
}

func cookieToken(value string) bool {
	for _, c := range value {
		if c < 0x21 || c > 0x7e || c == '"' || c == ';' || c == ',' || c == '\\' {
			return false
		}
	}
	return value != ""
}

func validateCSRF(data []byte) error {
	f, err := object(data, []string{"csrfToken"}, []string{"preauthToken", "expiresAt"})
	if err != nil {
		return err
	}
	if _, err := text(f["csrfToken"]); err != nil {
		return err
	}
	if token, ok := f["preauthToken"]; ok {
		value, err := text(token)
		if err != nil || !cookieToken(value) {
			return errInvalidResult
		}
		_, err = instant(f["expiresAt"])
		return err
	}
	if _, ok := f["expiresAt"]; ok {
		return errInvalidResult
	}
	return nil
}

func decodeFailure(data []byte, status int) (*operatorhttp.AuthFailure, error) {
	f, err := object(data, []string{"code", "outcome", "message", "retryable"}, []string{"details", "fieldErrors", "sessionRevoked"})
	if err != nil || status < 400 || status > 599 {
		return nil, errInvalidResult
	}
	var wire struct {
		Code           string            `json:"code"`
		Outcome        string            `json:"outcome"`
		Message        string            `json:"message"`
		Retryable      bool              `json:"retryable"`
		FieldErrors    map[string]string `json:"fieldErrors"`
		SessionRevoked *bool             `json:"sessionRevoked"`
	}
	if json.Unmarshal(data, &wire) != nil || !slices.Contains([]string{"committed", "not_committed", "unknown", "unavailable", "indeterminate"}, wire.Outcome) {
		return nil, errInvalidResult
	}
	if wire.Code == "PasswordChangeRateLimited" && (wire.SessionRevoked == nil || status != http.StatusTooManyRequests) {
		return nil, errInvalidResult
	}
	if wire.Code != "PasswordChangeRateLimited" && wire.SessionRevoked != nil {
		return nil, errInvalidResult
	}
	allowed := map[string]int{
		"InvalidArgument": 400, "InvalidRequest": 400, "InvalidCredentials": 401, "Unauthenticated": 401, "InvalidOrigin": 403, "InvalidCsrfToken": 403, "Forbidden": 403,
		"CurrentPasswordIncorrect": 403, "InvalidDisplayName": 422, "PasswordRejected": 422, "LoginRateLimited": 429, "PasswordChangeRateLimited": 429,
		"AuthUnavailable": 503, "AuthStorageUnavailable": 503, "AuthUpdateOutcomeUnknown": 503, "SessionStorageUnavailable": 503, "SessionUpdateOutcomeUnknown": 503,
		"AccountStorageUnavailable": 503, "AccountUpdateOutcomeUnknown": 503, "CommandConflict": 409, "RateLimited": 429,
	}
	if allowed[wire.Code] != status {
		return nil, errInvalidResult
	}
	unknown := slices.Contains([]string{"AuthUpdateOutcomeUnknown", "SessionUpdateOutcomeUnknown", "AccountUpdateOutcomeUnknown"}, wire.Code)
	if (unknown && wire.Outcome != "unknown") || (!unknown && wire.Outcome != "not_committed" && wire.Outcome != "unavailable") ||
		(wire.Code == "PasswordChangeRateLimited" && wire.Outcome != "not_committed") {
		return nil, errInvalidResult
	}
	retryAfter := 0
	if raw, ok := f["details"]; ok {
		details, err := object(raw, nil, []string{"retryAfterSeconds"})
		if err != nil {
			return nil, err
		}
		if raw, ok := details["retryAfterSeconds"]; ok {
			if json.Unmarshal(raw, &retryAfter) != nil || retryAfter < 1 {
				return nil, errInvalidResult
			}
		}
	}
	if raw, ok := f["fieldErrors"]; ok {
		fields, err := object(raw, nil, []string{"login", "password", "currentPassword", "newPassword", "displayName", "email"})
		if err != nil || status != http.StatusUnprocessableEntity {
			return nil, errInvalidResult
		}
		for _, v := range fields {
			value, err := text(v)
			if err != nil || !slices.Contains([]string{"Required", "TooShort", "TooLong", "InvalidFormat", "InvalidCharacters"}, value) {
				return nil, errInvalidResult
			}
		}
	}
	return &operatorhttp.AuthFailure{Status: status, Code: wire.Code, Outcome: wire.Outcome, Retryable: wire.Retryable, RetryAfter: retryAfter, FieldErrors: wire.FieldErrors, SessionRevoked: wire.SessionRevoked}, nil
}
