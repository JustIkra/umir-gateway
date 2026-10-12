package operator

import (
	"errors"
	"strings"
	"testing"
)

func wantFieldError(t *testing.T, err error, field string, code FieldCode) {
	t.Helper()
	var got *FieldError
	if !errors.As(err, &got) || got.Field != field || got.Code != code {
		t.Errorf("error = %v, want %s %s", err, field, code)
	}
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
	for _, tc := range []struct {
		raw  string
		code FieldCode
	}{
		{"", CodeRequired},
		{"\u3000\t", CodeRequired}, // only whitespace
		{" Я ", CodeTooShort},
		{strings.Repeat("я", 81), CodeTooLong},
		{"a\x00b", CodeInvalidCharacters},
		{"bad\xffname", CodeInvalidCharacters},
		{"Опе\uFFFDратор", CodeInvalidCharacters},
	} {
		_, err := CanonicalDisplayName(tc.raw)
		wantFieldError(t, err, "displayName", tc.code)
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
	for _, tc := range []struct {
		password string
		code     FieldCode
	}{
		{"", CodeRequired},
		{"1234567", CodeTooShort},
		{"\u00e9\u00e9\u00e9\u00e9", CodeTooShort}, // 4 precomposed code points
		{strings.Repeat("🙂", 33), CodeTooLong},
		{"bad utf8\xff", CodeInvalidCharacters},
		{"password\uFFFD", CodeInvalidCharacters}, // what encoding/json makes of invalid UTF-8 or a lone surrogate
	} {
		err := CheckPassword(tc.password)
		wantFieldError(t, err, "newPassword", tc.code)
		if err != nil && tc.password != "" && strings.Contains(err.Error(), tc.password) {
			t.Errorf("error echoes the password: %v", err)
		}
	}
}
