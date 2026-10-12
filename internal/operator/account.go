package operator

import (
	"errors"
	"strings"
	"unicode"
)

const (
	maxProfileID    = 128
	maxPasswordHash = 512
)

// Account is the single persisted operator profile.
type Account struct {
	ProfileID         string
	Login             string
	DisplayName       string
	PasswordHash      string
	CredentialVersion int64
}

// Profile is the account view returned to the operator; it excludes credentials.
type Profile struct {
	ID          string
	Login       string
	DisplayName string
}

func (a Account) Profile() Profile {
	return Profile{ID: a.ProfileID, Login: a.Login, DisplayName: a.DisplayName}
}

var (
	// ErrStorageUnavailable reports a storage failure known to precede the commit: nothing changed.
	ErrStorageUnavailable = errors.New("account storage unavailable")
	// ErrUpdateOutcomeUnknown reports a commit whose result cannot be determined.
	ErrUpdateOutcomeUnknown = errors.New("account update outcome unknown")
)

// Store persists the whole State in one atomic commit. Replace wraps ErrStorageUnavailable only for
// failures known to precede the commit; every other failure is treated as an unknown outcome.
type Store interface {
	Replace(next State) error
}

// PasswordHasher owns the password hash format.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encoded string) (bool, error)
	Check(encoded string) error
}

// ValidateAccount checks persisted fields; its errors name the field and never contain values.
func ValidateAccount(a Account) error {
	switch {
	case a.ProfileID == "" || len(a.ProfileID) > maxProfileID || strings.ContainsFunc(a.ProfileID, func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r)
	}):
		return errors.New("account profileID: expected 1 to 128 visible ASCII characters")
	case ValidateLogin(a.Login) != nil:
		return errors.New("account login: invalid")
	case !isCanonicalDisplayName(a.DisplayName):
		return errors.New("account displayName: expected canonical display name")
	case a.PasswordHash == "" || len(a.PasswordHash) > maxPasswordHash || strings.ContainsFunc(a.PasswordHash, func(r rune) bool {
		return r < '!' || r > '~'
	}):
		return errors.New("account passwordHash: expected 1 to 512 printable ASCII characters")
	case a.CredentialVersion < 1:
		return errors.New("account credentialVersion: expected positive integer")
	}
	return nil
}

func isCanonicalDisplayName(name string) bool {
	canonical, err := CanonicalDisplayName(name)
	return err == nil && canonical == name
}
