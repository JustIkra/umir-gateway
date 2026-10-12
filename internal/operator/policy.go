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

// FieldCode is a stable, machine-readable reason; the client maps it to text in its own language.
type FieldCode string

const (
	CodeRequired          FieldCode = "Required"
	CodeTooShort          FieldCode = "TooShort"
	CodeTooLong           FieldCode = "TooLong"
	CodeInvalidFormat     FieldCode = "InvalidFormat"
	CodeInvalidCharacters FieldCode = "InvalidCharacters"
)

// FieldError rejects one request field with a code; it never contains the submitted value.
type FieldError struct {
	Field string
	Code  FieldCode
}

func (e *FieldError) Error() string { return e.Field + ": " + string(e.Code) }

// validText rejects invalid UTF-8. A literal U+FFFD is valid text; input that a decoder would turn into
// U+FFFD (invalid bytes, unpaired surrogate escapes) is rejected where it is decoded.
func validText(s string) bool {
	return utf8.ValidString(s)
}

// lengthCode reports why a value of n code points is outside [lo, hi], or "" when it is inside.
func lengthCode(n, lo, hi int) FieldCode {
	switch {
	case n == 0:
		return CodeRequired
	case n < lo:
		return CodeTooShort
	case n > hi:
		return CodeTooLong
	}
	return ""
}

// CanonicalDisplayName trims Unicode whitespace and normalizes to NFC before counting code points.
func CanonicalDisplayName(raw string) (string, error) {
	reject := func(code FieldCode) error { return &FieldError{Field: "displayName", Code: code} }
	if !validText(raw) {
		return "", reject(CodeInvalidCharacters)
	}
	name := norm.NFC.String(strings.TrimFunc(raw, unicode.IsSpace))
	if strings.ContainsFunc(name, unicode.IsControl) {
		return "", reject(CodeInvalidCharacters)
	}
	if code := lengthCode(utf8.RuneCountInString(name), minDisplayName, maxDisplayName); code != "" {
		return "", reject(code)
	}
	return name, nil
}

// ValidateLogin accepts the immutable login. It is compared exactly, so surrounding whitespace is rejected.
// Only the account file carries a login, so one code is enough.
func ValidateLogin(login string) error {
	if !validText(login) || login == "" || utf8.RuneCountInString(login) > maxLogin ||
		strings.ContainsFunc(login, unicode.IsControl) || strings.TrimFunc(login, unicode.IsSpace) != login {
		return &FieldError{Field: "login", Code: CodeInvalidFormat}
	}
	return nil
}

// CheckPassword accepts 8 to 32 code points of valid UTF-8; length is the only rule in this phase.
// Passwords are never trimmed, normalized or truncated.
func CheckPassword(password string) error {
	reject := func(code FieldCode) error { return &FieldError{Field: "newPassword", Code: code} }
	if password == "" {
		return reject(CodeRequired)
	}
	if !validText(password) {
		return reject(CodeInvalidCharacters)
	}
	if code := lengthCode(utf8.RuneCountInString(password), minPassword, maxPassword); code != "" {
		return reject(code)
	}
	return nil
}
