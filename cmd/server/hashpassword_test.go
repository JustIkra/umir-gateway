package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/adapters/argon2id"
)

var phcLine = regexp.MustCompile(`^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}\n$`)

// noTerminal is a pipe or a file on stdin.
type noTerminal struct{}

func (noTerminal) IsTerminal() bool              { return false }
func (noTerminal) ReadPassword() ([]byte, error) { return nil, errors.New("not a terminal") }

// fakeTerminal answers the prompts with lines, without echo, and counts the reads.
type fakeTerminal struct {
	lines []string
	reads int
}

func (f *fakeTerminal) IsTerminal() bool { return true }

func (f *fakeTerminal) ReadPassword() ([]byte, error) {
	if f.reads == len(f.lines) {
		return nil, io.EOF
	}
	f.reads++
	return []byte(f.lines[f.reads-1]), nil
}

// unreadable fails the test when the command reads plain stdin while a terminal is attached.
type unreadable struct{ t *testing.T }

func (u unreadable) Read([]byte) (int, error) {
	u.t.Error("stdin was read past the no-echo terminal")
	return 0, io.EOF
}

func runHash(t *testing.T, args []string, stdin io.Reader, tty terminal) (code int, stdout, stderr string) {
	t.Helper()
	hasher, err := argon2id.New(argon2id.Baseline, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	code = hashPassword(args, stdin, tty, &out, &errOut, hasher.Hash)
	return code, out.String(), errOut.String()
}

func TestHashPasswordFromPipeKeepsThePassword(t *testing.T) {
	verifier, err := argon2id.New(argon2id.Baseline, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, password string }{
		{"  spaced pass  \n", "  spaced pass  "},
		{"pässwörd\r\n", "pässwörd"},
		{"12345678", "12345678"},
		{strings.Repeat("🙂", 32) + "\n", strings.Repeat("🙂", 32)},
		{"tab\tinside\n", "tab\tinside"},
	} {
		code, stdout, stderr := runHash(t, nil, strings.NewReader(tc.input), noTerminal{})
		if code != 0 || stderr != "" || !phcLine.MatchString(stdout) {
			t.Fatalf("%q: code %d, stdout %q, stderr %q", tc.input, code, stdout, stderr)
		}
		if ok, err := verifier.Verify(tc.password, strings.TrimSuffix(stdout, "\n")); err != nil || !ok {
			t.Errorf("%q: hash does not verify the exact password: %v", tc.input, err)
		}
	}
}

func TestHashPasswordRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		args  []string
		input string
	}{
		"7 code points":  {nil, "пароль1\n"},
		"33 code points": {nil, strings.Repeat("я", 33) + "\n"},
		"empty":          {nil, "\n"},
		"invalid UTF-8":  {nil, "password\xff\n"},
		"two lines":      {nil, "first password\nsecond password\n"},
		"too long":       {nil, strings.Repeat("x", 2000)},
		"argument":       {[]string{"secret password"}, "correct horse\n"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runHash(t, tc.args, strings.NewReader(tc.input), noTerminal{})
			if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "hash-password: ") {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			for _, secret := range append(strings.Split(strings.TrimSpace(tc.input), "\n"), tc.args...) {
				if secret != "" && strings.Contains(stderr, secret) {
					t.Errorf("stderr repeats %q: %q", secret, stderr)
				}
			}
		})
	}
}

func TestHashPasswordTerminalDoesNotEcho(t *testing.T) {
	tty := &fakeTerminal{lines: []string{"typed in secret", "typed in secret"}}
	code, stdout, stderr := runHash(t, nil, unreadable{t}, tty)
	if code != 0 || tty.reads != 2 || !phcLine.MatchString(stdout) || stderr != "Password: \nRepeat password: \n" {
		t.Fatalf("code %d, reads %d, stdout %q, stderr %q", code, tty.reads, stdout, stderr)
	}
	mismatch := &fakeTerminal{lines: []string{"typed in secret", "typed in secreT"}}
	code, stdout, stderr = runHash(t, nil, unreadable{t}, mismatch)
	if code != 1 || stdout != "" || strings.Contains(stderr, "typed") {
		t.Fatalf("mismatch: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestHashPasswordChildProcess(t *testing.T) {
	const password = "child process password"
	child := exec.Command(os.Args[0], "-test.run=^TestGatewayChildProcess$")
	child.Env = childEnvironment(map[string]string{
		"UMIR_GATEWAY_TEST_CHILD": "1",
		"UMIR_GATEWAY_TEST_ARGS":  "hash-password",
		"GORACE":                  "atexit_sleep_ms=0",
	})
	child.Stdin = strings.NewReader(password + "\n")
	var stdout, stderr strings.Builder
	child.Stdout, child.Stderr = &stdout, &stderr
	if err := child.Run(); err != nil {
		t.Fatalf("hash-password: %v, stderr %q", err, stderr.String())
	}
	selected := fmt.Sprintf("$m=%d,t=%d,p=%d$", argon2id.Selected.MemoryKiB, argon2id.Selected.Iterations, argon2id.Selected.Parallelism)
	if !phcLine.MatchString(stdout.String()) || !strings.Contains(stdout.String(), selected) || stderr.String() != "" {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
	for _, value := range append(child.Args, child.Env...) {
		if strings.Contains(value, password) {
			t.Errorf("password in the child's arguments or environment: %q", value)
		}
	}
}
