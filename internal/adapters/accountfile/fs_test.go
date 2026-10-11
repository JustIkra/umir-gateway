package accountfile

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (i fakeInfo) Name() string       { return "account.json" }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func TestCheckOwnership(t *testing.T) {
	uid := uint32(os.Geteuid())
	if err := checkOwnership(fakeInfo{mode: 0o600, uid: uid}, 0o600, int(uid)); err != nil {
		t.Fatal(err)
	}
	for _, info := range []fakeInfo{
		{mode: 0o644, uid: uid},
		{mode: 0o400, uid: uid},
		{mode: 0o600 | fs.ModeSetuid, uid: uid},
		{mode: 0o600, uid: uid + 1},
	} {
		if err := checkOwnership(info, 0o600, int(uid)); err == nil {
			t.Errorf("checkOwnership(%v, uid %d) accepted", info.mode, info.uid)
		}
	}
}
