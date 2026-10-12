package accountfile

import (
	"errors"
	"fmt"
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
		Validate:     operator.ValidateState,
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
  "schemaVersion": 2,
  "profileID": "PROFILE1",
  "login": "operator",
  "displayName": "Оператор",
  "passwordHash": "` + fakeHash + `",
  "credentialVersion": 3,
  "sessions": []
}
`

// accountOnlyFile is the first schema, written before sessions were persisted.
const accountOnlyFile = `{
  "schemaVersion": 1,
  "profileID": "PROFILE1",
  "login": "operator",
  "displayName": "Оператор",
  "passwordHash": "` + fakeHash + `",
  "credentialVersion": 3
}
`

const validSession = `{"digest": "` + testDigest + `", "rememberMe": false, "credentialVersion": 3, ` +
	`"createdAt": "2026-10-11T09:00:00Z", "lastSeenAt": "2026-10-11T09:10:00Z", "expiresAt": "2026-10-11T17:00:00Z"}`

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func withSessions(sessions string) string {
	return strings.Replace(validFile, `"sessions": []`, `"sessions": [`+sessions+`]`, 1)
}

func TestOpenLoadsExistingFileAndIgnoresBootstrap(t *testing.T) {
	path := filepath.Join(accountDir(t), "account.json")
	writeAccount(t, path, validFile)
	other := Bootstrap{Login: "intruder", DisplayName: "Другой", PasswordHash: fakeHash}
	state, store, err := Open(path, other, testOptions())
	if err != nil || store == nil {
		t.Fatal(err)
	}
	want := operator.Account{ProfileID: "PROFILE1", Login: "operator", DisplayName: "Оператор", PasswordHash: fakeHash, CredentialVersion: 3}
	if state.Account != want || len(state.Sessions) != 0 {
		t.Fatalf("state = %+v", state)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != validFile {
		t.Fatalf("existing file was rewritten: %v", err)
	}
}

func TestOpenBootstrapsAbsentFile(t *testing.T) {
	path := filepath.Join(accountDir(t), "account.json")
	state, _, err := Open(path, testBootstrap(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	account := state.Account
	if account.ProfileID != "PROFILE1" || account.CredentialVersion != 1 || account.Login != "operator" || len(state.Sessions) != 0 {
		t.Fatalf("state = %+v", state)
	}
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), `"schemaVersion": 2`) {
		t.Fatalf("bootstrap file is not schema 2: %s %v", data, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", info, err)
	}
	reopened, _, err := Open(path, Bootstrap{}, testOptions())
	if err != nil || reopened.Account != account || len(reopened.Sessions) != 0 {
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
		"hash byte":    {Login: "operator", DisplayName: "Оператор", PasswordHash: "$argon2id$v=19$\xff"},
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
		"schema 3":       strings.Replace(validFile, `"schemaVersion": 2`, `"schemaVersion": 3`, 1),
		"missing schema": strings.Replace(validFile, `"schemaVersion": 2,`, ``, 1),
		"schema 2 without sessions": strings.Replace(validFile, `,
  "sessions": []`, ``, 1),
		"schema 1 with sessions":   strings.Replace(accountOnlyFile, `"credentialVersion": 3`, `"credentialVersion": 3, "sessions": []`, 1),
		"sessions not a list":      strings.Replace(validFile, `"sessions": []`, `"sessions": {}`, 1),
		"sessions null":            strings.Replace(validFile, `"sessions": []`, `"sessions": null`, 1),
		"session not an object":    withSessions(`1`),
		"unknown session field":    withSessions(strings.Replace(validSession, `"rememberMe"`, `"role": "admin", "rememberMe"`, 1)),
		"case-variant session key": withSessions(strings.Replace(validSession, `"digest"`, `"Digest"`, 1)),
		"duplicate session key":    withSessions(strings.Replace(validSession, `"rememberMe": false`, `"rememberMe": false, "rememberMe": true`, 1)),
		"missing session field":    withSessions(strings.Replace(validSession, `"rememberMe": false, `, ``, 1)),
		"invalid session time":     withSessions(strings.Replace(validSession, `"2026-10-11T09:00:00Z"`, `"yesterday"`, 1)),
		"invalid session digest":   withSessions(strings.Replace(validSession, testDigest, "not-a-digest", 1)),
		"duplicate session":        withSessions(validSession + ", " + validSession),
		"invalid UTF-8":            strings.Replace(validFile, "Оператор", "Опе\xffратор", 1),
		"version zero":             strings.Replace(validFile, `"credentialVersion": 3`, `"credentialVersion": 0`, 1),
		"not an object":            `[1]`,
		"case-variant key":         strings.Replace(validFile, `"credentialVersion": 3`, `"credentialVersion": 3, "LOGIN": "intruder"`, 1),
		"case-variant only":        strings.Replace(validFile, `"schemaVersion"`, `"SchemaVersion"`, 1),
		"lone surrogate":           strings.Replace(validFile, "Оператор", `Опе\ud800ратор`, 1),
		"too large":                strings.Replace(validFile, "Оператор", strings.Repeat("я", maxFileSize), 1),
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

func TestOpenEnforcesThe32SessionRecordLimit(t *testing.T) {
	for _, tc := range []struct {
		count   int
		wantErr bool
	}{
		{count: 32},
		{count: 33, wantErr: true},
	} {
		var records []string
		for i := range tc.count {
			records = append(records, fmt.Sprintf(
				`{"digest":"%064x","rememberMe":false,"credentialVersion":3,"createdAt":"2026-10-11T09:00:00Z","lastSeenAt":"2026-10-11T09:10:00Z","expiresAt":"2026-10-11T17:00:00Z"}`,
				i+1,
			))
		}
		content := withSessions(strings.Join(records, ","))
		path := filepath.Join(accountDir(t), "account.json")
		writeAccount(t, path, content)
		state, _, err := Open(path, testBootstrap(), testOptions())
		if tc.wantErr {
			if err == nil || !strings.Contains(err.Error(), "session") {
				t.Errorf("%d valid session records: error = %v, want session-limit rejection", tc.count, err)
			}
			if data, readErr := os.ReadFile(path); readErr != nil || string(data) != content {
				t.Errorf("%d records: rejected file was changed (%v)", tc.count, readErr)
			}
			continue
		}
		if err != nil || len(state.Sessions) != 32 {
			t.Errorf("%d valid session records: loaded %d, error %v", tc.count, len(state.Sessions), err)
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

func TestOpenKeepsALiteralReplacementCharacter(t *testing.T) {
	for name, spelled := range map[string]string{"raw": "Опе\xef\xbf\xbdратор", "escaped": `Опе\ufffdратор`} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(accountDir(t), "account.json")
			writeAccount(t, path, strings.Replace(validFile, "Оператор", spelled, 1))
			state, _, err := Open(path, testBootstrap(), testOptions())
			if err != nil || state.Account.DisplayName != "Опе\uFFFDратор" {
				t.Fatalf("state = %+v, %v", state, err)
			}
		})
	}
}

func TestOpenMigratesAccountOnlyFile(t *testing.T) {
	path := filepath.Join(accountDir(t), "account.json")
	writeAccount(t, path, accountOnlyFile)
	state, _, err := Open(path, testBootstrap(), testOptions())
	want := operator.Account{ProfileID: "PROFILE1", Login: "operator", DisplayName: "Оператор", PasswordHash: fakeHash, CredentialVersion: 3}
	if err != nil || state.Account != want || len(state.Sessions) != 0 {
		t.Fatalf("state = %+v, %v", state, err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(migrated), `"schemaVersion": 2`) || !strings.Contains(string(migrated), `"sessions": []`) {
		t.Fatalf("file was not migrated: %s %v", migrated, err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("migrated file: %v, %v", info, err)
	}
	reopened, _, err := Open(path, Bootstrap{}, testOptions())
	if err != nil || reopened.Account != want {
		t.Fatalf("reopened = %+v, %v", reopened, err)
	}
	if again, err := os.ReadFile(path); err != nil || string(again) != string(migrated) {
		t.Errorf("a schema 2 file was rewritten on open: %v", err)
	}
}
