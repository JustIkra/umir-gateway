package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/JustIkra/umir-gateway/internal/adapters/argon2id"
	"github.com/JustIkra/umir-gateway/internal/operator"
)

// maxPasswordInput bounds what hash-password reads from a pipe; 32 code points take at most 128 bytes.
const maxPasswordInput = 1 << 10

// terminal is stdin when it is an interactive terminal.
type terminal interface {
	IsTerminal() bool
	// ReadPassword reads one line without echoing it.
	ReadPassword() ([]byte, error)
}

type stdinTerminal struct{ fd int }

func (t stdinTerminal) IsTerminal() bool              { return term.IsTerminal(t.fd) }
func (t stdinTerminal) ReadPassword() ([]byte, error) { return term.ReadPassword(t.fd) }

// runHashPassword wires hash-password to the process's standard streams. It needs no configuration.
func runHashPassword(args []string) int {
	hasher, err := argon2id.New(argon2id.Selected, rand.Reader)
	if err != nil {
		log.Print(err)
		return 1
	}
	return hashPassword(args, os.Stdin, stdinTerminal{fd: int(os.Stdin.Fd())}, os.Stdout, os.Stderr, hasher.Hash)
}

// hashPassword reads one password from stdin and prints only its Argon2id PHC string. The password
// never appears in arguments, the environment or any output.
func hashPassword(args []string, stdin io.Reader, tty terminal, stdout, stderr io.Writer, hash func(string) (string, error)) int {
	fail := func(message string) int {
		if _, err := fmt.Fprintln(stderr, "hash-password: "+message); err != nil {
			return 2 // the failure could not even be reported
		}
		return 1
	}
	if len(args) != 0 {
		return fail("takes no arguments; send the password on stdin")
	}
	password, err := readPassword(stdin, tty, stderr)
	if err != nil {
		return fail(err.Error())
	}
	if err := operator.CheckPassword(password); err != nil {
		var field *operator.FieldError
		if errors.As(err, &field) && field.Code == operator.CodeInvalidCharacters {
			return fail("password must be valid UTF-8 text")
		}
		return fail("password must contain 8 to 32 characters")
	}
	encoded, err := hash(password)
	if err != nil {
		return fail(fmt.Sprintf("hash: %v", err))
	}
	if _, err := fmt.Fprintln(stdout, encoded); err != nil {
		return fail(fmt.Sprintf("write: %v", err))
	}
	return 0
}

// readPassword asks twice on a terminal, without echo. From a pipe it takes exactly one line; one
// trailing newline, with an optional carriage return before it, is not part of the password.
func readPassword(stdin io.Reader, tty terminal, stderr io.Writer) (string, error) {
	if tty.IsTerminal() {
		first, err := prompt(tty, stderr, "Password: ")
		if err != nil {
			return "", err
		}
		second, err := prompt(tty, stderr, "Repeat password: ")
		if err != nil {
			return "", err
		}
		if first != second {
			return "", errors.New("passwords do not match")
		}
		return first, nil
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxPasswordInput+1))
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	if len(data) > maxPasswordInput {
		return "", errors.New("stdin is too long; send one password line")
	}
	line, newline := strings.CutSuffix(string(data), "\n")
	if newline {
		line = strings.TrimSuffix(line, "\r")
	}
	if strings.Contains(line, "\n") {
		return "", errors.New("send exactly one password line")
	}
	return line, nil
}

// prompt asks on stderr and reads the answer without echo. The terminal does not echo the Enter key
// either, so the prompt line is ended here.
func prompt(tty terminal, stderr io.Writer, question string) (string, error) {
	if _, err := io.WriteString(stderr, question); err != nil {
		return "", fmt.Errorf("prompt: %w", err)
	}
	answer, readErr := tty.ReadPassword()
	_, writeErr := io.WriteString(stderr, "\n")
	if err := errors.Join(readErr, writeErr); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(answer), nil
}
