package accountfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// faultFS wraps the real file system and fails one chosen step.
type faultFS struct {
	osFileSystem
	failCreate, failWrite, failRename, failSyncDir bool
	renameThenFail                                 bool // perform the rename, then report failure
	failReadAfterRename                            bool
	renamed                                        bool
}

var errInjected = errors.New("injected storage failure")

func (f *faultFS) CreateTemp(dir string) (tempFile, error) {
	if f.failCreate {
		return nil, errInjected
	}
	file, err := f.osFileSystem.CreateTemp(dir)
	if err != nil || !f.failWrite {
		return file, err
	}
	return failingWrite{file}, nil
}

type failingWrite struct{ tempFile }

func (failingWrite) Write([]byte) (int, error) { return 0, errInjected }

func (f *faultFS) Rename(from, to string) error {
	if f.failRename {
		return errInjected
	}
	if err := f.osFileSystem.Rename(from, to); err != nil {
		return err
	}
	f.renamed = true
	if f.renameThenFail {
		return errInjected
	}
	return nil
}

func (f *faultFS) SyncDir(dir string) error {
	if f.failSyncDir {
		return errInjected
	}
	return f.osFileSystem.SyncDir(dir)
}

func (f *faultFS) ReadFile(path string) ([]byte, error) {
	if f.renamed && f.failReadAfterRename {
		return nil, errInjected
	}
	return f.osFileSystem.ReadFile(path)
}

func openWith(t *testing.T, fs fileSystem) (string, operator.Account, *Store) {
	t.Helper()
	path := filepath.Join(accountDir(t), "account.json")
	writeAccount(t, path, validFile)
	account, store, err := open(path, Bootstrap{}, testOptions(), fs)
	if err != nil {
		t.Fatal(err)
	}
	return path, account, store
}

func renamedAccount(account operator.Account) operator.Account {
	account.DisplayName = "Новое имя"
	return account
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("temporary file left: %s", entry.Name())
		}
	}
}

func TestReplaceCommitsWholeFile(t *testing.T) {
	path, account, store := openWith(t, osFileSystem{uid: os.Geteuid()})
	next := renamedAccount(account)
	if err := store.Replace(next); err != nil {
		t.Fatal(err)
	}
	reopened, _, err := Open(path, Bootstrap{}, testOptions())
	if err != nil || reopened != next {
		t.Fatalf("reopened = %+v, %v", reopened, err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("file: %v, %v", info, err)
	}
	assertNoTempFiles(t, filepath.Dir(path))
}

func TestReplaceClassifiesFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fs         *faultFS
		definite   bool // the failure is known to precede the commit
		wantNewDoc bool
	}{
		{"create temp", &faultFS{failCreate: true}, true, false},
		{"write temp", &faultFS{failWrite: true}, true, false},
		{"rename refused", &faultFS{failRename: true}, true, false},
		{"rename reported failure after commit", &faultFS{renameThenFail: true}, false, true},
		{"directory flush", &faultFS{failSyncDir: true}, false, true},
		{"re-read", &faultFS{failReadAfterRename: true}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.fs.osFileSystem = osFileSystem{uid: os.Geteuid()}
			path, account, store := openWith(t, tc.fs)
			err := store.Replace(renamedAccount(account))
			definite := errors.Is(err, operator.ErrStorageUnavailable) && !errors.Is(err, operator.ErrUpdateOutcomeUnknown)
			unknown := errors.Is(err, operator.ErrUpdateOutcomeUnknown) && !errors.Is(err, operator.ErrStorageUnavailable)
			if (tc.definite && !definite) || (!tc.definite && !unknown) {
				t.Fatalf("Replace error = %v, want definite=%v", err, tc.definite)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if gotNew := strings.Contains(string(data), "Новое имя"); gotNew != tc.wantNewDoc {
				t.Errorf("file has new document = %v", gotNew)
			}
			assertNoTempFiles(t, filepath.Dir(path))
		})
	}
}

func TestOpenIgnoresStrayTempFile(t *testing.T) {
	path, account, _ := openWith(t, osFileSystem{uid: os.Geteuid()})
	stray := filepath.Join(filepath.Dir(path), ".account-123.tmp")
	if err := os.WriteFile(stray, []byte("{partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, store, err := Open(path, Bootstrap{}, testOptions())
	if err != nil || reopened != account {
		t.Fatalf("reopened = %+v, %v", reopened, err)
	}
	if err := store.Replace(renamedAccount(account)); err != nil {
		t.Fatalf("Replace with stray temp file: %v", err)
	}
}

func TestConcurrentReplacesLeaveOneValidDocument(t *testing.T) {
	path, account, store := openWith(t, osFileSystem{uid: os.Geteuid()})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := account
			next.CredentialVersion = int64(10 + i)
			if err := store.Replace(next); err != nil {
				t.Errorf("Replace %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	reopened, _, err := Open(path, Bootstrap{}, testOptions())
	if err != nil || reopened.CredentialVersion < 10 || reopened.CredentialVersion > 17 {
		t.Fatalf("reopened = %+v, %v", reopened, err)
	}
}
