package admission_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInternalHasNoProcessLocalAdmissionLimiter(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path is unavailable")
	}
	root := filepath.Dir(filepath.Dir(source))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range []string{"TemporaryMemory", "registrationLimits"} {
			if strings.Contains(string(data), forbidden) {
				t.Errorf("process-local admission limiter %q remains in %s", forbidden, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
