// Package accountfile persists the operator account as one JSON file.
package accountfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

const schemaVersion = 1

// Bootstrap creates the account only when the file does not exist yet.
type Bootstrap struct {
	Login        string
	DisplayName  string
	PasswordHash string
}

type Options struct {
	// NewProfileID creates the opaque ID of a bootstrapped account.
	NewProfileID func() (string, error)
	// Validate rejects account fields before they are returned or first written.
	Validate func(operator.Account) error
}

// Store replaces the account file; it serializes its own writes.
type Store struct {
	mu      sync.Mutex
	path    string
	dir     string
	fs      fileSystem
	current []byte // committed file content, used to classify a failed rename
}

type document struct {
	SchemaVersion     int    `json:"schemaVersion"`
	ProfileID         string `json:"profileID"`
	Login             string `json:"login"`
	DisplayName       string `json:"displayName"`
	PasswordHash      string `json:"passwordHash"`
	CredentialVersion int64  `json:"credentialVersion"`
}

var errInvalidFile = errors.New("operator account file: invalid JSON document")

// Open loads the account at path. An absent file is created from bootstrap; an existing file is
// authoritative and never rewritten here. Errors never contain account values.
func Open(path string, bootstrap Bootstrap, opts Options) (operator.Account, *Store, error) {
	return open(path, bootstrap, opts, osFileSystem{uid: os.Geteuid()})
}

func open(path string, bootstrap Bootstrap, opts Options, fs fileSystem) (operator.Account, *Store, error) {
	if opts.NewProfileID == nil || opts.Validate == nil {
		return operator.Account{}, nil, errors.New("accountfile: NewProfileID and Validate are required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return operator.Account{}, nil, errors.New("OPERATOR_STORE_PATH: expected a clean absolute path")
	}
	store := &Store{path: path, dir: filepath.Dir(path), fs: fs}
	if err := fs.CheckDir(store.dir); err != nil {
		return operator.Account{}, nil, fmt.Errorf("OPERATOR_STORE_PATH directory: %w", err)
	}
	data, err := fs.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		account, err := store.bootstrap(bootstrap, opts)
		return account, store, err
	}
	if err != nil {
		return operator.Account{}, nil, fmt.Errorf("OPERATOR_STORE_PATH: %w", err)
	}
	account, err := decode(data)
	if err == nil {
		err = opts.Validate(account)
	}
	if err != nil {
		return operator.Account{}, nil, fmt.Errorf("operator account file: %w", err)
	}
	store.current = data
	return account, store, nil
}

func (s *Store) bootstrap(bootstrap Bootstrap, opts Options) (operator.Account, error) {
	if bootstrap.Login == "" || bootstrap.DisplayName == "" || bootstrap.PasswordHash == "" {
		return operator.Account{}, errors.New("operator account file is absent: bootstrap login, display name and password hash are required")
	}
	profileID, err := opts.NewProfileID()
	if err != nil {
		return operator.Account{}, fmt.Errorf("operator profile ID: %w", err)
	}
	account := operator.Account{
		ProfileID: profileID, Login: bootstrap.Login, DisplayName: bootstrap.DisplayName,
		PasswordHash: bootstrap.PasswordHash, CredentialVersion: 1,
	}
	if err := opts.Validate(account); err != nil {
		return operator.Account{}, fmt.Errorf("operator bootstrap: %w", err)
	}
	data, err := encode(account)
	if err != nil {
		return operator.Account{}, err
	}
	if err := s.write(data); err != nil {
		return operator.Account{}, fmt.Errorf("create operator account file: %w", err)
	}
	s.current = data
	return account, nil
}

func encode(account operator.Account) ([]byte, error) {
	data, err := json.MarshalIndent(document{
		SchemaVersion: schemaVersion, ProfileID: account.ProfileID, Login: account.Login,
		DisplayName: account.DisplayName, PasswordHash: account.PasswordHash, CredentialVersion: account.CredentialVersion,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: encode account: %w", operator.ErrStorageUnavailable, err)
	}
	return append(data, '\n'), nil
}

// decode accepts exactly one object with known, unique fields; JSON would silently replace invalid UTF-8.
func decode(data []byte) (operator.Account, error) {
	if !utf8.Valid(data) || rejectDuplicateKeys(data) != nil {
		return operator.Account{}, errInvalidFile
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc document
	if err := decoder.Decode(&doc); err != nil {
		return operator.Account{}, errInvalidFile
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return operator.Account{}, errInvalidFile
	}
	if doc.SchemaVersion != schemaVersion {
		return operator.Account{}, errors.New("operator account file: unsupported schemaVersion")
	}
	return operator.Account{
		ProfileID: doc.ProfileID, Login: doc.Login, DisplayName: doc.DisplayName,
		PasswordHash: doc.PasswordHash, CredentialVersion: doc.CredentialVersion,
	}, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errInvalidFile
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, isKey := token.(string)
		if err != nil || !isKey || seen[key] {
			return errInvalidFile
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errInvalidFile
		}
	}
	return nil
}

// Replace commits next as the whole account file. A failure known to precede the commit wraps
// operator.ErrStorageUnavailable; any failure after the commit point wraps operator.ErrUpdateOutcomeUnknown.
func (s *Store) Replace(next operator.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := encode(next)
	if err != nil {
		return err
	}
	if err := s.write(data); err != nil {
		return err
	}
	s.current = data
	return nil
}

// write follows: unique temp file, mode 0600, full content, flush, rename, directory flush, re-read.
func (s *Store) write(data []byte) error {
	temp, err := s.fs.CreateTemp(s.dir)
	if err != nil {
		return definite("create temporary file", err)
	}
	if err := fill(temp, data); err != nil {
		return errors.Join(definite("write temporary file", err), s.fs.Remove(temp.Name()))
	}
	if err := s.fs.Rename(temp.Name(), s.path); err != nil {
		removeErr := s.fs.Remove(temp.Name())
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		// rename(2) normally leaves the target untouched on error; confirm before calling it definite.
		if committed, readErr := s.fs.ReadFile(s.path); readErr == nil && s.current != nil && bytes.Equal(committed, s.current) {
			return errors.Join(definite("replace account file", err), removeErr)
		}
		return ambiguous("replace account file", err)
	}
	if err := s.fs.SyncDir(s.dir); err != nil {
		return ambiguous("flush account directory", err)
	}
	committed, err := s.fs.ReadFile(s.path)
	if err != nil {
		return ambiguous("re-read account file", err)
	}
	if !bytes.Equal(committed, data) {
		return ambiguous("re-read account file", errors.New("content differs from the written document"))
	}
	return nil
}

func fill(temp tempFile, data []byte) error {
	err := temp.Chmod(0o600)
	if err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	return errors.Join(err, temp.Close())
}

func definite(step string, err error) error {
	return fmt.Errorf("%w: %s: %w", operator.ErrStorageUnavailable, step, err)
}

func ambiguous(step string, err error) error {
	return fmt.Errorf("%w: %s: %w", operator.ErrUpdateOutcomeUnknown, step, err)
}
