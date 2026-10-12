package argon2id

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerify(t *testing.T) {
	hasher, err := New(Baseline, bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	format := regexp.MustCompile(`^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if !format.MatchString(encoded) {
		t.Fatalf("hash format: %s", encoded)
	}
	want := argon2.IDKey([]byte("correct horse battery staple"), bytes.Repeat([]byte{7}, 16), 2, 19456, 1, 32)
	if _, _, key, err := decode(encoded); err != nil || !bytes.Equal(key, want) {
		t.Fatalf("key differs from argon2.IDKey: %v", err)
	}
	for password, wantOK := range map[string]bool{"correct horse battery staple": true, "correct horse battery stapler": false, "": false} {
		if ok, err := hasher.Verify(password, encoded); err != nil || ok != wantOK {
			t.Errorf("Verify(%q) = %v, %v", password, ok, err)
		}
	}
	if err := hasher.Check(encoded); err != nil {
		t.Errorf("Check: %v", err)
	}
}

func TestVerifyUsesParametersFromTheHash(t *testing.T) {
	stronger, err := New(Params{MemoryKiB: 32768, Iterations: 3, Parallelism: 2}, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := stronger.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := New(Baseline, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := baseline.Verify("correct horse battery staple", encoded); !ok || err != nil {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
}

func TestCheckRejectsMalformedOrWeakHashes(t *testing.T) {
	hasher, err := New(Baseline, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	salt, key := "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, encoded := range []string{
		"",
		"$argon2i$v=19$m=19456,t=2,p=1$" + salt + "$" + key,
		"$argon2id$v=16$m=19456,t=2,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=4096,t=2,p=1$" + salt + "$" + key,    // below baseline
		"$argon2id$v=19$m=19456,t=1,p=1$" + salt + "$" + key,   // below baseline
		"$argon2id$v=19$m=4194304,t=2,p=1$" + salt + "$" + key, // memory above the bound
		"$argon2id$v=19$m=019456,t=2,p=1$" + salt + "$" + key,  // non-canonical number
		"$argon2id$v=19$m=19456,t=2,p=1,x=1$" + salt + "$" + key,
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$" + key,          // short salt
		"$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$AAAA",    // short key
		"$argon2id$v=19$m=19456,t=2,p=1$" + salt + "=$" + key, // padded base64
		"$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$" + key + "$",
	} {
		if err := hasher.Check(encoded); err == nil {
			t.Errorf("Check(%q) accepted", encoded)
		} else if encoded != "" && strings.Contains(err.Error(), salt) {
			t.Errorf("error echoes the hash: %v", err)
		}
		if _, err := hasher.Verify("password", encoded); err == nil {
			t.Errorf("Verify(%q) accepted", encoded)
		}
	}
}

func TestNewRejectsWeakParametersAndMissingRandom(t *testing.T) {
	for _, params := range []Params{
		{MemoryKiB: 19455, Iterations: 2, Parallelism: 1},
		{MemoryKiB: 19456, Iterations: 1, Parallelism: 1},
		{MemoryKiB: 19456, Iterations: 2, Parallelism: 0},
	} {
		if _, err := New(params, bytes.NewReader(nil)); err == nil {
			t.Errorf("New(%+v) accepted", params)
		}
	}
	if _, err := New(Baseline, nil); err == nil {
		t.Error("New without random source accepted")
	}
}

func TestHashReportsRandomFailure(t *testing.T) {
	broken := errors.New("entropy unavailable")
	hasher, err := New(Baseline, iotest.ErrReader(broken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hasher.Hash("correct horse battery staple"); !errors.Is(err, broken) {
		t.Fatalf("Hash error = %v", err)
	}
}

func TestSelectedParameters(t *testing.T) {
	hasher, err := New(Selected, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$", Selected.MemoryKiB, Selected.Iterations, Selected.Parallelism)
	if !strings.HasPrefix(encoded, prefix) || Selected.MemoryKiB < Baseline.MemoryKiB {
		t.Fatalf("hash %q does not use the selected cost", encoded)
	}
}

// BenchmarkHash measures one hash at each cost; run it on the deployment VM before changing Selected.
func BenchmarkHash(b *testing.B) {
	for _, tc := range []struct {
		name   string
		params Params
	}{{"baseline", Baseline}, {"selected", Selected}} {
		b.Run(tc.name, func(b *testing.B) {
			hasher, err := New(tc.params, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				if _, err := hasher.Hash("correct horse battery staple"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
