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

func TestW2ServeRequiresRedisLimiterURL(t *testing.T) {
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
	select {
	case err := <-exited:
		if err == nil {
			t.Fatal("serve started without the shared Redis limiter configuration")
		}
	case <-time.After(5 * time.Second):
		if err := child.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("stop child after startup timeout: %v", err)
		}
		t.Fatal("serve did not refuse to start without Redis limiter settings")
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

func TestW1CheckCommand(t *testing.T) {
	for name, tc := range map[string]struct {
		args      []string
		testChild bool
		ok        bool
	}{
		"no arguments":        {[]string{"server"}, false, true},
		"serve":               {[]string{"server", "serve"}, false, true},
		"healthcheck":         {[]string{"server", "healthcheck"}, false, true},
		"clear-sessions":      {[]string{"server", "clear-sessions"}, false, true},
		"typo flag":           {[]string{"server", "--typo"}, false, false},
		"short flag":          {[]string{"server", "-x"}, false, false},
		"test flag outside":   {[]string{"server", "-test.run=X"}, false, false},
		"migrate":             {[]string{"server", "migrate"}, false, false},
		"serve with extra":    {[]string{"server", "serve", "extra"}, false, false},
		"test flag in child":  {[]string{"server", "-test.run=X"}, true, true},
		"typo flag in child":  {[]string{"server", "--typo"}, true, false},
		"serve in child":      {[]string{"server", "-test.run=X", "serve"}, true, true},
		"typo with test flag": {[]string{"server", "-test.run=X", "--typo"}, true, false},
		"serve then extra":    {[]string{"server", "serve", "-test.run=X", "x"}, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkCommand(tc.args, tc.testChild); (err == nil) != tc.ok {
				t.Fatalf("checkCommand(%v, %v) = %v", tc.args, tc.testChild, err)
			}
		})
	}
}

func TestW1TypoFlagDoesNotStartServer(t *testing.T) {
	_, exited := startChild(t, "--typo", operatorEnv(t))
	select {
	case err := <-exited:
		if err == nil {
			t.Fatal("a mistyped option started the server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the process kept running")
	}
}
