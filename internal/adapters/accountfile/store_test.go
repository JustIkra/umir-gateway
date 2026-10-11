package accountfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// fakeHash is recognisable in error text, so tests can prove it is never echoed.
const fakeHash = "$argon2id$v=19$m=19456,t=2,p=1$FAKESALTFAKESALTFAKESA$FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEY1"

func accountDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "operator")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testOptions() Options {
	return Options{
		NewProfileID: func() (string, error) { return "PROFILE1", nil },
		Validate:     operator.ValidateAccount,
	}
}

func testBootstrap() Bootstrap {
	return Bootstrap{Login: "operator", DisplayName: "Оператор", PasswordHash: fakeHash}
}

func writeAccount(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const validFile = `{
  "schemaVersion": 1,
  "profileID": "PROFILE1",
  "login": "operator",
  "displayName": "Оператор",
  "passwordHash": "` + fakeHash + `",
  "credentialVersion": 3
}
`

func TestOpenLoadsExistingFileAndIgnoresBootstrap(t *testing.T) {
	path := filepath.Join(accountDir(t), "account.json")
	writeAccount(t, path, validFile)
	other := Bootstrap{Login: "intruder", DisplayName: "Другой", PasswordHash: fakeHash}
	account, store, err := Open(path, other, testOptions())
	if err != nil || store == nil {
		t.Fatal(err)
	}
	want := operator.Account{ProfileID: "PROFILE1", Login: "operator", DisplayName: "Оператор", PasswordHash: fakeHash, CredentialVersion: 3}
	if account != want {
		t.Fatalf("account = %+v", account)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != validFile {
		t.Fatalf("existing file was rewritten: %v", err)
	}
}

func TestOpenBootstrapsAbsentFile(t *testing.T) {
	path := filepath.Join(accountDir(t), "account.json")
	account, _, err := Open(path, testBootstrap(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if account.ProfileID != "PROFILE1" || account.CredentialVersion != 1 || account.Login != "operator" {
		t.Fatalf("account = %+v", account)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", info, err)
	}
	reopened, _, err := Open(path, Bootstrap{}, testOptions())
	if err != nil || reopened != account {
		t.Fatalf("reopened = %+v, %v", reopened, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory has %d entries (%v), want only the account file", len(entries), err)
	}
}

func TestOpenRejectsMissingBootstrapWithoutCreatingFile(t *testing.T) {
	for name, bootstrap := range map[string]Bootstrap{
		"login":        {DisplayName: "Оператор", PasswordHash: fakeHash},
		"displayName":  {Login: "operator", PasswordHash: fakeHash},
		"passwordHash": {Login: "operator", DisplayName: "Оператор"},
		"invalid":      {Login: "operator", DisplayName: " Оператор", PasswordHash: fakeHash},
	} {
		path := filepath.Join(accountDir(t), "account.json")
		_, _, err := Open(path, bootstrap, testOptions())
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), fakeHash) || strings.Contains(err.Error(), "Оператор") {
			t.Errorf("%s: error echoes a value: %v", name, err)
		}
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s: file created", name)
		}
	}
}

func TestOpenRejectsCorruptFileWithoutResetting(t *testing.T) {
	for name, content := range map[string]string{
		"invalid JSON":   `{"schemaVersion": 1,`,
		"unknown field":  strings.Replace(validFile, `"credentialVersion"`, `"role": "admin", "credentialVersion"`, 1),
		"duplicate key":  strings.Replace(validFile, `"credentialVersion": 3`, `"credentialVersion": 3, "credentialVersion": 4`, 1),
		"trailing data":  validFile + "{}",
		"schema 2":       strings.Replace(validFile, `"schemaVersion": 1`, `"schemaVersion": 2`, 1),
		"missing schema": strings.Replace(validFile, `"schemaVersion": 1,`, ``, 1),
		"invalid UTF-8":  strings.Replace(validFile, "Оператор", "Опе\xffратор", 1),
		"version zero":   strings.Replace(validFile, `"credentialVersion": 3`, `"credentialVersion": 0`, 1),
		"not an object":  `[1]`,
		"too large":      strings.Replace(validFile, "Оператор", strings.Repeat("я", maxFileSize), 1),
	} {
		path := filepath.Join(accountDir(t), "account.json")
		writeAccount(t, path, content)
		_, _, err := Open(path, testBootstrap(), testOptions())
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), fakeHash) {
			t.Errorf("%s: error echoes the hash: %v", name, err)
		}
		if data, readErr := os.ReadFile(path); readErr != nil || string(data) != content {
			t.Errorf("%s: corrupt file was replaced (%v)", name, readErr)
		}
	}
}

func TestOpenRejectsUnsafePaths(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"relative": func(t *testing.T) string { return "operator/account.json" },
		"unclean":  func(t *testing.T) string { return accountDir(t) + "/../operator/account.json" },
		"file mode": func(t *testing.T) string {
			path := filepath.Join(accountDir(t), "account.json")
			writeAccount(t, path, validFile)
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"dir mode": func(t *testing.T) string {
			dir := accountDir(t)
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "account.json")
		},
		"file symlink": func(t *testing.T) string {
			dir := accountDir(t)
			target := filepath.Join(dir, "real.json")
			writeAccount(t, target, validFile)
			path := filepath.Join(dir, "account.json")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"dir symlink": func(t *testing.T) string {
			dir := accountDir(t)
			link := filepath.Join(filepath.Dir(dir), "linked")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "account.json")
		},
		"missing dir": func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent", "account.json") },
	}
	for name, path := range cases {
		if _, _, err := Open(path(t), testBootstrap(), testOptions()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
