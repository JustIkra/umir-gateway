package protocol

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFileAdmission(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      os.FileMode
		maximum   os.FileMode
		size      int
		limit     int64
		wantError string
	}{
		{"credential", 0600, 0600, 64, 64, ""},
		{"config", 0644, 0644, 1024, 1 << 20, ""},
		{"empty", 0600, 0600, 0, 64, ""},
		{"credential-read-only", 0400, 0600, 64, 64, "unsafe file"},
		{"credential-public", 0644, 0600, 64, 64, "unsafe file"},
		{"config-writable", 0666, 0644, 64, 1 << 20, "unsafe file"},
		{"credential-oversize", 0600, 0600, 65, 64, "file bound"},
		{"config-oversize", 0644, 0644, (1 << 20) + 1, 1 << 20, "file bound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(privateFileDir(t), "input")
			want := bytes.Repeat([]byte("a"), tc.size)
			if err := os.WriteFile(path, want, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, os.Getuid(), os.Getgid()); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			data, err := readFile(path, tc.limit, tc.maximum)
			if tc.wantError != "" {
				if err == nil || err.Error() != tc.wantError || data != nil {
					t.Fatalf("admission data/error: %d/%v, want %s", len(data), err, tc.wantError)
				}
				return
			}
			if err != nil || !bytes.Equal(data, want) {
				t.Fatalf("private file contents changed: %v", err)
			}
		})
	}
}

func TestPrivateFileSymlinkAndDirectoryRejection(t *testing.T) {
	dir := privateFileDir(t)
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "parent")
	if err := os.Symlink(dir, parent); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want string
	}{
		{link, "file unavailable"},
		{filepath.Join(parent, "input"), "unsafe parent"},
		{dir, "unsafe file"},
	} {
		if _, err := readFile(tc.path, 64, 0600); err == nil || err.Error() != tc.want {
			t.Errorf("path admission: %v, want %s", err, tc.want)
		}
	}
}
