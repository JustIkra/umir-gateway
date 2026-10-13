package journal

import (
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"
)

func TestG3JournalBoundsAndCopiesRetainedPaths(t *testing.T) {
	for name, path := range map[string]string{"large ASCII": "/api/warehouse/" + strings.Repeat("x", 1_000_000), "unicode": "/" + strings.Repeat("界", 2000), "short slice": strings.Repeat("s", 1_000_000)[:32]} {
		t.Run(name, func(t *testing.T) {
			j := newTestJournal(t, 2)
			for range 3 {
				j.Append(Entry{Source: SourceRequest, Path: path, Outcome: OutcomeRejected})
			}
			entries := j.Entries(0)
			if len(entries) != 2 {
				t.Fatal("ring count changed")
			}
			for _, e := range entries {
				if len(e.Path) > 1024 {
					t.Errorf("retained %d path bytes", len(e.Path))
				}
				if !strings.HasPrefix(path, e.Path) || !utf8.ValidString(e.Path) {
					t.Error("path prefix corrupted")
				}
				if unsafe.StringData(e.Path) == unsafe.StringData(path) {
					t.Error("retained caller backing bytes")
				}
			}
		})
	}
}
