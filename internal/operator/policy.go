// Package operator keeps the single operator account, its sessions and CSRF contexts.
package operator

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	minDisplayName = 2
	maxDisplayName = 80
	minPassword    = 8
	maxPassword    = 32
	maxLogin       = 128
)

// FieldError rejects one request field with a message that is safe to show; it never contains the value.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

// validText rejects invalid UTF-8 and U+FFFD, which encoding/json substitutes for invalid bytes and
// lone surrogates; accepting it would store a value other than the one the client sent.
func validText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, utf8.RuneError)
}

// CanonicalDisplayName trims Unicode whitespace and normalizes to NFC before counting code points.
func CanonicalDisplayName(raw string) (string, error) {
	reject := func(message string) error { return &FieldError{Field: "displayName", Message: message} }
	if !validText(raw) {
		return "", reject("must be valid UTF-8 text")
	}
	name := norm.NFC.String(strings.TrimFunc(raw, unicode.IsSpace))
	if strings.ContainsFunc(name, unicode.IsControl) {
		return "", reject("must not contain control characters")
	}
	if n := utf8.RuneCountInString(name); n < minDisplayName || n > maxDisplayName {
		return "", reject("must contain 2 to 80 characters")
	}
	return name, nil
}

// ValidateLogin accepts the immutable login. It is compared exactly, so surrounding whitespace is rejected.
func ValidateLogin(login string) error {
	if !validText(login) || login == "" || utf8.RuneCountInString(login) > maxLogin ||
		strings.ContainsFunc(login, unicode.IsControl) || strings.TrimFunc(login, unicode.IsSpace) != login {
		return &FieldError{Field: "login", Message: "must be 1 to 128 characters without control characters or surrounding spaces"}
	}
	return nil
}

// CheckPassword accepts 8 to 32 code points of valid UTF-8; length is the only rule in this phase.
// Passwords are never trimmed, normalized or truncated.
func CheckPassword(password string) error {
	if !validText(password) {
		return &FieldError{Field: "newPassword", Message: "must be valid UTF-8 text"}
	}
	if n := utf8.RuneCountInString(password); n < minPassword || n > maxPassword {
		return &FieldError{Field: "newPassword", Message: "must contain 8 to 32 characters"}
	}
	return nil
}
