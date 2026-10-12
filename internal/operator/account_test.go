package operator

import (
	"strings"
	"testing"
)

func TestValidateAccount(t *testing.T) {
	valid := Account{ProfileID: "P7Q2", Login: "operator", DisplayName: "Оператор", PasswordHash: "hash:x", CredentialVersion: 1}
	if err := ValidateAccount(valid); err != nil {
		t.Fatal(err)
	}
	broken := map[string]func(*Account){
		"profileID":          func(a *Account) { a.ProfileID = "" },
		"profileID spaces":   func(a *Account) { a.ProfileID = "a b" },
		"login":              func(a *Account) { a.Login = " operator" },
		"displayName":        func(a *Account) { a.DisplayName = " Оператор" }, // not canonical
		"passwordHash":       func(a *Account) { a.PasswordHash = "" },
		"passwordHash byte":  func(a *Account) { a.PasswordHash = "$argon2id$v=19$\xff" },
		"passwordHash space": func(a *Account) { a.PasswordHash = "$argon2id$ v=19" },
		"passwordHash long":  func(a *Account) { a.PasswordHash = strings.Repeat("a", 513) },
		"credentialVersion":  func(a *Account) { a.CredentialVersion = 0 },
	}
	for name, change := range broken {
		account := valid
		change(&account)
		err := ValidateAccount(account)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "Оператор") || strings.Contains(err.Error(), "operator") {
			t.Errorf("%s: error echoes a value: %v", name, err)
		}
	}
	if valid.Profile() != (Profile{ID: "P7Q2", Login: "operator", DisplayName: "Оператор"}) {
		t.Errorf("Profile() = %+v", valid.Profile())
	}
}
