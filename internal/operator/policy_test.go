package operator

import (
	"errors"
	"strings"
	"testing"
)

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	var field *FieldError
	if !errors.As(err, &field) {
		t.Fatalf("error %v is not a FieldError", err)
	}
	return field.Field
}

func TestCanonicalDisplayName(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"  Оператор\u00a0\t", "Оператор"},
		{"e\u0301e\u0301", "\u00e9\u00e9"}, // NFC turns four code points into two
		{"Ян", "Ян"},
		{strings.Repeat("я", 80), strings.Repeat("я", 80)},
	} {
		got, err := CanonicalDisplayName(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("CanonicalDisplayName(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{"", " Я ", "\u3000", strings.Repeat("я", 81), "a\x00b", "bad\xffname", "Опе\uFFFDратор"} {
		if _, err := CanonicalDisplayName(raw); err == nil || fieldOf(t, err) != "displayName" {
			t.Errorf("CanonicalDisplayName(%q) error = %v", raw, err)
		}
	}
}

func TestValidateLogin(t *testing.T) {
	for _, login := range []string{"operator", "оператор-1"} {
		if err := ValidateLogin(login); err != nil {
			t.Errorf("ValidateLogin(%q) = %v", login, err)
		}
	}
	for _, login := range []string{"", " operator", "operator ", "a\tb", strings.Repeat("x", 129), "bad\xff", "oper\uFFFDtor"} {
		if err := ValidateLogin(login); err == nil {
			t.Errorf("ValidateLogin(%q) accepted", login)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	for _, password := range []string{
		"12345678",                     // simple values are allowed
		"жёлтый д",                     // 8 code points, 15 bytes
		strings.Repeat("🙂", 32),        // 32 code points, 128 bytes
		"  spaces kept  ",              // never trimmed
		"e\u0301e\u0301e\u0301e\u0301", // 8 code points; never normalized to 4
	} {
		if err := CheckPassword(password); err != nil {
			t.Errorf("CheckPassword(%q) = %v", password, err)
		}
	}
	for _, password := range []string{
		"1234567",
		"\u00e9\u00e9\u00e9\u00e9", // 4 precomposed code points
		strings.Repeat("🙂", 33),
		"bad utf8\xff",
		"password\uFFFD", // what encoding/json makes of invalid UTF-8 or a lone surrogate
	} {
		err := CheckPassword(password)
		if err == nil || fieldOf(t, err) != "newPassword" {
			t.Errorf("CheckPassword(%q) error = %v", password, err)
		}
		if err != nil && strings.Contains(err.Error(), password) {
			t.Errorf("error echoes the password: %v", err)
		}
	}
}
