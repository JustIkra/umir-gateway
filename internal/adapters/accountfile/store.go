// Package accountfile persists the operator account as one JSON file.
package accountfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
	"github.com/JustIkra/umir-gateway/internal/strictjson"
)

const (
	accountOnlySchema = 1
	schemaVersion     = 2
)

// Bootstrap creates the account only when the file does not exist yet.
type Bootstrap struct {
	Login        string
	DisplayName  string
	PasswordHash string
}

type Options struct {
	// NewProfileID creates the opaque ID of a bootstrapped account.
	NewProfileID func() (string, error)
	// Validate rejects the state before it is returned or first written.
	Validate func(operator.State) error
}

// Store replaces the account file; it serializes its own writes.
type Store struct {
	mu      sync.Mutex
	path    string
	dir     string
	fs      fileSystem
	current []byte // committed file content, used to classify a failed rename
}

// document is the account file. Schema 1 has no sessions; schema 2 always has the sessions list.
type document struct {
	SchemaVersion     int               `json:"schemaVersion"`
	ProfileID         string            `json:"profileID"`
	Login             string            `json:"login"`
	DisplayName       string            `json:"displayName"`
	PasswordHash      string            `json:"passwordHash"`
	CredentialVersion int64             `json:"credentialVersion"`
	Sessions          []sessionDocument `json:"sessions"`
}

type sessionDocument struct {
	Digest            string    `json:"digest"`
	RememberMe        bool      `json:"rememberMe"`
	CredentialVersion int64     `json:"credentialVersion"`
	CreatedAt         time.Time `json:"createdAt"`
	LastSeenAt        time.Time `json:"lastSeenAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

var errInvalidFile = errors.New("operator account file: invalid JSON document")

// The exact keys of each schema and of a session record. encoding/json matches field names
// case-insensitively, so an exact check is what keeps "LOGIN" or "Digest" from loading.
var (
	schemaKeys = map[int]map[string]bool{
		accountOnlySchema: {
			"schemaVersion": true, "profileID": true, "login": true,
			"displayName": true, "passwordHash": true, "credentialVersion": true,
		},
		schemaVersion: {
			"schemaVersion": true, "profileID": true, "login": true,
			"displayName": true, "passwordHash": true, "credentialVersion": true, "sessions": true,
		},
	}
	sessionKeys = map[string]bool{
		"digest": true, "rememberMe": true, "credentialVersion": true,
		"createdAt": true, "lastSeenAt": true, "expiresAt": true,
	}
)

// Open loads the account and its sessions at path. An absent file is created from bootstrap; an
// existing file is authoritative. A schema 1 file is rewritten once as schema 2 with no sessions, and a
// failed rewrite stops startup instead of resetting anything. Errors never contain account values.
func Open(path string, bootstrap Bootstrap, opts Options) (operator.State, *Store, error) {
	return open(path, bootstrap, opts, osFileSystem{uid: os.Geteuid()})
}

func open(path string, bootstrap Bootstrap, opts Options, fs fileSystem) (operator.State, *Store, error) {
	if opts.NewProfileID == nil || opts.Validate == nil {
		return operator.State{}, nil, errors.New("accountfile: NewProfileID and Validate are required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return operator.State{}, nil, errors.New("OPERATOR_STORE_PATH: expected a clean absolute path")
	}
	store := &Store{path: path, dir: filepath.Dir(path), fs: fs}
	if err := fs.CheckDir(store.dir); err != nil {
		return operator.State{}, nil, fmt.Errorf("OPERATOR_STORE_PATH directory: %w", err)
	}
	data, err := fs.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		state, err := store.bootstrap(bootstrap, opts)
		return state, store, err
	}
	if err != nil {
		return operator.State{}, nil, fmt.Errorf("OPERATOR_STORE_PATH: %w", err)
	}
	state, version, err := decode(data)
	if err == nil {
		err = opts.Validate(state)
	}
	if err != nil {
		return operator.State{}, nil, fmt.Errorf("operator account file: %w", err)
	}
	store.current = data
	if version == accountOnlySchema {
		if err := store.commit(state); err != nil {
			return operator.State{}, nil, fmt.Errorf("migrate operator account file to schema %d: %w", schemaVersion, err)
		}
	}
	return state, store, nil
}

func (s *Store) bootstrap(bootstrap Bootstrap, opts Options) (operator.State, error) {
	if bootstrap.Login == "" || bootstrap.DisplayName == "" || bootstrap.PasswordHash == "" {
		return operator.State{}, errors.New("operator account file is absent: bootstrap login, display name and password hash are required")
	}
	profileID, err := opts.NewProfileID()
	if err != nil {
		return operator.State{}, fmt.Errorf("operator profile ID: %w", err)
	}
	state := operator.State{Account: operator.Account{
		ProfileID: profileID, Login: bootstrap.Login, DisplayName: bootstrap.DisplayName,
		PasswordHash: bootstrap.PasswordHash, CredentialVersion: 1,
	}}
	if err := opts.Validate(state); err != nil {
		return operator.State{}, fmt.Errorf("operator bootstrap: %w", err)
	}
	if err := s.commit(state); err != nil {
		return operator.State{}, fmt.Errorf("create operator account file: %w", err)
	}
	return state, nil
}

// encode writes the current schema; times are stored in UTC.
func encode(state operator.State) ([]byte, error) {
	sessions := make([]sessionDocument, 0, len(state.Sessions))
	for _, st := range state.Sessions {
		sessions = append(sessions, sessionDocument{
			Digest: st.Digest, RememberMe: st.RememberMe, CredentialVersion: st.CredentialVersion,
			CreatedAt: st.Created.UTC(), LastSeenAt: st.LastSeen.UTC(), ExpiresAt: st.ExpiresAt.UTC(),
		})
	}
	a := state.Account
	data, err := json.MarshalIndent(document{
		SchemaVersion: schemaVersion, ProfileID: a.ProfileID, Login: a.Login, DisplayName: a.DisplayName,
		PasswordHash: a.PasswordHash, CredentialVersion: a.CredentialVersion, Sessions: sessions,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: encode account: %w", operator.ErrStorageUnavailable, err)
	}
	return append(data, '\n'), nil
}

// decode accepts exactly one object of a known schema with exactly spelled, unique fields, and exactly
// spelled session records. Invalid UTF-8 and unpaired surrogate escapes, which JSON would silently turn
// into U+FFFD, reject the file.
func decode(data []byte) (operator.State, int, error) {
	if strictjson.CheckText(data) != nil {
		return operator.State{}, 0, errInvalidFile
	}
	fields, err := objectFields(data)
	if err != nil {
		return operator.State{}, 0, err
	}
	var version int
	if err := json.Unmarshal(fields["schemaVersion"], &version); err != nil {
		return operator.State{}, 0, errInvalidFile
	}
	keys, known := schemaKeys[version]
	if !known {
		return operator.State{}, 0, errors.New("operator account file: unsupported schemaVersion")
	}
	if !sameKeys(fields, keys) || version == schemaVersion && checkSessionKeys(fields["sessions"]) != nil {
		return operator.State{}, 0, errInvalidFile
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc document
	if err := decoder.Decode(&doc); err != nil {
		return operator.State{}, 0, errInvalidFile
	}
	state := operator.State{Account: operator.Account{
		ProfileID: doc.ProfileID, Login: doc.Login, DisplayName: doc.DisplayName,
		PasswordHash: doc.PasswordHash, CredentialVersion: doc.CredentialVersion,
	}}
	for _, st := range doc.Sessions {
		state.Sessions = append(state.Sessions, operator.StoredSession{
			Digest: st.Digest, RememberMe: st.RememberMe, CredentialVersion: st.CredentialVersion,
			Created: st.CreatedAt, LastSeen: st.LastSeenAt, ExpiresAt: st.ExpiresAt,
		})
	}
	return state, version, nil
}

// objectFields reads exactly one JSON object with unique keys and returns its members.
func objectFields(data []byte) (map[string]json.RawMessage, error) {
	fields, err := strictjson.Object(data)
	if err != nil {
		return nil, errInvalidFile
	}
	return fields, nil
}

func sameKeys(fields map[string]json.RawMessage, want map[string]bool) bool {
	if len(fields) != len(want) {
		return false
	}
	for key := range fields {
		if !want[key] {
			return false
		}
	}
	return true
}

// checkSessionKeys requires a list of objects, each with exactly the session record keys.
func checkSessionKeys(raw json.RawMessage) error {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' {
		return errInvalidFile
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return errInvalidFile
	}
	for _, item := range items {
		fields, err := objectFields(item)
		if err != nil || !sameKeys(fields, sessionKeys) {
			return errInvalidFile
		}
	}
	return nil
}

// Replace commits next as the whole account file. A failure known to precede the commit wraps
// operator.ErrStorageUnavailable; any failure after the commit point wraps operator.ErrUpdateOutcomeUnknown.
func (s *Store) Replace(next operator.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commit(next)
}

func (s *Store) commit(next operator.State) error {
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
