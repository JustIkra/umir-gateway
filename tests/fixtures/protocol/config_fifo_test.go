package protocol

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func privateFileDir(t *testing.T) string {
	t.Helper()
	root := os.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	dir, err := os.MkdirTemp(root, "gateway-private-file-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func TestReadFileFIFOWithoutWriterReturns(t *testing.T) {
	if path := os.Getenv("UMIR_FIFO_PROBE_PATH"); path != "" {
		limit, err := strconv.ParseInt(os.Getenv("UMIR_FIFO_PROBE_LIMIT"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		mode, err := strconv.ParseUint(os.Getenv("UMIR_FIFO_PROBE_MODE"), 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readFile(path, limit, os.FileMode(mode)); err == nil || err.Error() != "unsafe file" {
			t.Fatalf("FIFO admission: %v", err)
		}
		return
	}
	for _, consumer := range []struct {
		name  string
		limit int64
		mode  os.FileMode
	}{
		{"server-and-control-config", 1 << 20, 0644},
		{"server-and-control-credential", 64, 0600},
	} {
		t.Run(consumer.name, func(t *testing.T) {
			path := filepath.Join(privateFileDir(t), "input")
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, os.Getuid(), os.Getgid()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadFileFIFOWithoutWriterReturns$")
			cmd.Env = append(os.Environ(),
				"UMIR_FIFO_PROBE_PATH="+path,
				"UMIR_FIFO_PROBE_LIMIT="+strconv.FormatInt(consumer.limit, 10),
				"UMIR_FIFO_PROBE_MODE="+strconv.FormatUint(uint64(consumer.mode), 8),
				"GORACE=atexit_sleep_ms=0",
			)
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("private-file admission did not return within 750ms without a FIFO writer: %s", output)
			}
			if err != nil {
				t.Fatalf("FIFO admission process: %v: %s", err, output)
			}
		})
	}
}
