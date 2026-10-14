package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractActualTimeTZData(t *testing.T) {
	gorootBytes, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	goroot := strings.TrimSpace(string(gorootBytes))

	source, err := os.ReadFile(filepath.Join(goroot, "src/time/tzdata/zzipdata.go"))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(filepath.Join(goroot, "lib/time/zoneinfo.zip"))
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := extract(source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(embedded, archive) {
		t.Fatal("embedded dependency differs from toolchain archive")
	}
	for _, input := range [][]byte{[]byte("package tzdata"), []byte("package tzdata; var zipdata = \"wrong\""), []byte("package tzdata; const zipdata = 123"), []byte("package tzdata; const zipdata = \"a\" + \"b\"")} {
		if _, err := extract(input); err == nil {
			t.Fatal("different AST layout admitted")
		}
	}
}
