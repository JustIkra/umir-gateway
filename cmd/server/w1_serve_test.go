package main

import (
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// startChild runs main() in a child process with the given arguments and environment.
func startChild(t *testing.T, args string, environment map[string]string) (*exec.Cmd, <-chan error) {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=^TestGatewayChildProcess$")
	env := map[string]string{"UMIR_GATEWAY_TEST_CHILD": "1", "UMIR_GATEWAY_TEST_ARGS": args, "GORACE": "atexit_sleep_ms=0"}
	maps.Copy(env, environment)
	child.Env = childEnvironment(env)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	t.Cleanup(func() {
		if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("stop child: %v", err)
		}
	})
	return child, exited
}

// serve starts Gateway in the Auth mode with every service key given as a file, as the durable profile does.
func TestW1ServeSubcommandStartsServer(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer peer.Close()
	dir := t.TempDir()
	environment := operatorEnv(t)
	for name, secret := range map[string]string{"AUTH_SERVICE_KEY": "serve-auth-key", "AUTH_RUNTIME_SERVICE_KEY": "serve-runtime-key", "SERVING_SERVICE_KEY": "serve-serving-key", "WAREHOUSE_SERVICE_KEY": "serve-warehouse-key", "FEEDBACK_SERVICE_KEY": "serve-feedback-key"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		environment[name+"_FILE"] = path
		environment[name] = ""
	}
	port := freePort(t)
	maps.Copy(environment, map[string]string{"AUTH_URL": peer.URL, "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "PORT": port, "PRIVATE_PORT": freePort(t)})
	child, exited := startChild(t, "serve", environment)
	waitChildHealthy(t, "http://127.0.0.1:"+port, exited)
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("serve did not exit cleanly: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop on SIGTERM")
	}
}

func TestW1UnknownSubcommandIsRefused(t *testing.T) {
	for _, args := range []string{"migrate", "serve extra", "generation rotate"} {
		_, exited := startChild(t, args, operatorEnv(t))
		select {
		case err := <-exited:
			if err == nil {
				t.Errorf("%q started the server", args)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%q did not exit", args)
		}
	}
}
