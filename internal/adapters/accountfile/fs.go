package accountfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// maxFileSize bounds reading the account file; a valid account is far smaller.
const maxFileSize = 64 << 10

// fileSystem is the storage mechanism behind Store; tests inject failures through it.
type fileSystem interface {
	CheckDir(dir string) error
	ReadFile(path string) ([]byte, error)
	CreateTemp(dir string) (tempFile, error)
	Rename(from, to string) error
	SyncDir(dir string) error
	Remove(path string) error
}

type tempFile interface {
	Name() string
	Chmod(mode os.FileMode) error
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

type osFileSystem struct{ uid int }

func (f osFileSystem) CheckDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("expected a directory, not a file or symlink")
	}
	return checkOwnership(info, 0o700, f.uid)
}

// ReadFile refuses symlinks and checks the opened file itself, so a swap after a check cannot pass.
func (f osFileSystem) ReadFile(path string) (data []byte, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("expected a regular file")
	}
	if err := checkOwnership(info, 0o600, f.uid); err != nil {
		return nil, err
	}
	data, err = io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("account file exceeds %d bytes", maxFileSize)
	}
	return data, nil
}

func (osFileSystem) CreateTemp(dir string) (tempFile, error) {
	return os.CreateTemp(dir, ".account-*.tmp")
}

func (osFileSystem) Rename(from, to string) error { return os.Rename(from, to) }

func (osFileSystem) SyncDir(dir string) (err error) {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, handle.Close()) }()
	return handle.Sync()
}

func (osFileSystem) Remove(path string) error { return os.Remove(path) }

// checkOwnership requires exactly perm, no special bits and the process user as owner.
func checkOwnership(info os.FileInfo, perm os.FileMode, uid int) error {
	if info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != perm {
		return fmt.Errorf("expected mode %#o", perm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid {
		return errors.New("expected the gateway process user as owner")
	}
	return nil
}
