package protocol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/JustIkra/umir-gateway/tests/fixtures/catalog"
)

const ProfileRequestPath = "/run/umir-fixtures/profile-request.json"

func CatalogCall(ctx context.Context, cfg Config, body []byte) ([]byte, int, error) {
	input, err := catalog.ValidateRequest(body)
	if err != nil || input.Project != cfg.Project {
		return nil, 0, errors.New("invalid catalog request")
	}
	if err := CheckControlSocket(cfg.ControlSocket); err != nil {
		return nil, 0, err
	}
	credential, err := ReadCredential(cfg.ControlCredentialFile)
	if err != nil {
		return nil, 0, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", cfg.ControlSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://fixture"+catalog.Path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	reply, err := client.Do(request)
	if err != nil {
		return nil, 0, errors.New("catalog control unavailable")
	}
	result, readErr := io.ReadAll(io.LimitReader(reply.Body, 65537))
	closeErr := reply.Body.Close()
	if readErr != nil || closeErr != nil || len(result) > 65536 {
		return nil, 0, errors.Join(errors.New("catalog response unavailable"), readErr, closeErr)
	}
	if err := catalog.ValidateReply(result, input, reply.StatusCode); err != nil {
		return nil, 0, err
	}
	return result, reply.StatusCode, nil
}
func CatalogFromFile() error {
	cfg, _, err := LoadConfig(ConfigPath)
	if err != nil {
		return err
	}
	body, err := readFile(ProfileRequestPath, 65536, 0600)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, status, err := CatalogCall(ctx, cfg, body)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(append(result, '\n')); err != nil {
		return err
	}
	if status != 200 {
		return errors.New("catalog request refused")
	}
	return nil
}
