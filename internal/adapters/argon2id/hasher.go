// Package argon2id hashes operator passwords as Argon2id PHC strings.
package argon2id

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the costs written into new hashes; existing hashes keep their own.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// Baseline is the OWASP minimum: 19 MiB, 2 iterations, parallelism 1.
var Baseline = Params{MemoryKiB: 19 * 1024, Iterations: 2, Parallelism: 1}

const (
	saltLen = 16
	keyLen  = 32
	// The upper bounds stop a hash from the account file or configuration from exhausting the process.
	maxMemoryKiB   = 1 << 20
	maxIterations  = 16
	maxParallelism = 16
	minEncodedLen  = 16
	maxEncodedLen  = 64
)

var errMalformed = errors.New("argon2id: malformed or unsupported password hash")

type Hasher struct {
	params Params
	random io.Reader
}

func New(params Params, random io.Reader) (*Hasher, error) {
	if random == nil {
		return nil, errors.New("argon2id: random source required")
	}
	if err := params.check(); err != nil {
		return nil, err
	}
	return &Hasher{params: params, random: random}, nil
}

func (p Params) check() error {
	if p.MemoryKiB < Baseline.MemoryKiB || p.MemoryKiB > maxMemoryKiB ||
		p.Iterations < Baseline.Iterations || p.Iterations > maxIterations ||
		p.Parallelism < 1 || p.Parallelism > maxParallelism {
		return errors.New("argon2id: parameters outside the allowed range")
	}
	return nil
}

func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(h.random, salt); err != nil {
		return "", fmt.Errorf("argon2id salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.MemoryKiB, h.params.Parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s", argon2.Version, h.params.encode(),
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func (h *Hasher) Verify(password, encoded string) (bool, error) {
	params, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}

func (h *Hasher) Check(encoded string) error {
	_, _, _, err := decode(encoded)
	return err
}

func (p Params) encode() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.MemoryKiB, p.Iterations, p.Parallelism)
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return Params{}, nil, nil, errMalformed
	}
	var params Params
	var parallelism uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.MemoryKiB, &params.Iterations, &parallelism); err != nil || parallelism > maxParallelism {
		return Params{}, nil, nil, errMalformed
	}
	params.Parallelism = uint8(parallelism)
	// Re-encoding rejects leading zeros, signs and trailing fields that Sscanf tolerates.
	if params.encode() != parts[3] || params.check() != nil {
		return Params{}, nil, nil, errMalformed
	}
	salt, saltErr := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	key, keyErr := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if saltErr != nil || keyErr != nil || len(salt) < minEncodedLen || len(salt) > maxEncodedLen || len(key) < minEncodedLen || len(key) > maxEncodedLen {
		return Params{}, nil, nil, errMalformed
	}
	return params, salt, key, nil
}
