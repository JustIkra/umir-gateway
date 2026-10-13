package catalog

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestProvenanceRejectsUnrelatedArchiveAndBinary(t *testing.T) {
	root := t.TempDir()
	archive := []byte("not a ZIP")
	binary := []byte("compiled executable")
	for name, data := range map[string][]byte{"zoneinfo.zip": archive, "fixture-server": binary} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := Provenance{Owner: "gateway", Version: "go1.26.9-embedded", ArchiveSHA256: digest(archive), ArchiveBytes: len(archive), EmbeddedArchiveSHA256: digest(archive), BuildToolchain: "go1.26.9", ToolchainImageID: "sha256:" + digest(binary), ToolchainSourceSHA256: digest(binary), BinarySHA256: digest(binary), SourceKind: "go-time-tzdata"}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(context.Background(), data, archive, binary); err == nil {
		t.Fatal("invalid archive accepted")
	}
	p.BinarySHA256 = digest(archive)
	data, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(context.Background(), data, archive, binary); err == nil {
		t.Fatal("wrong executable accepted")
	}
}

func TestMeasuredToolchainArchiveAndTamperRejection(t *testing.T) {
	gorootBytes, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	goroot := strings.TrimSpace(string(gorootBytes))

	archive, err := os.ReadFile(filepath.Join(goroot, "lib/time/zoneinfo.zip"))
	if err != nil {
		t.Fatal(err)
	}
	binary := append([]byte("executable-prefix"), archive...)
	p := Provenance{Owner: "gateway", Version: "go1.26.9-embedded", ArchiveSHA256: digest(archive), ArchiveBytes: len(archive), EmbeddedArchiveSHA256: digest(archive), BuildToolchain: "go1.26.9", ToolchainImageID: "sha256:" + digest(binary), ToolchainSourceSHA256: digest(binary), BinarySHA256: digest(binary), SourceKind: "go-time-tzdata"}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := inspect(context.Background(), data, archive, binary)
	if err != nil || !fact.Ready || fact.ProvenanceSHA256 != digest(data) {
		t.Fatal("actual archive not observed", err)
	}
	for _, mutation := range []func(*Provenance){func(p *Provenance) { p.ArchiveSHA256 = strings.Repeat("0", 64) }, func(p *Provenance) { p.ArchiveBytes++ }, func(p *Provenance) { p.EmbeddedArchiveSHA256 = strings.Repeat("0", 64) }, func(p *Provenance) { p.BinarySHA256 = strings.Repeat("0", 64) }, func(p *Provenance) { p.Version = "go1.26.9" }, func(p *Provenance) { p.BuildToolchain = "go1.26.5" }, func(p *Provenance) { p.SourceKind = "warehouse-embedded" }} {
		changed := p
		mutation(&changed)
		body, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inspect(context.Background(), body, archive, binary); err == nil {
			t.Fatal("tampered provenance admitted")
		}
	}
	if _, err := inspect(context.Background(), data, archive, []byte("other binary")); err == nil {
		t.Fatal("other binary admitted")
	}
	for _, body := range []string{string(data) + "{}", strings.TrimSuffix(string(data), "}") + `,"owner":"gateway"}`, strings.Replace(string(data), `"owner"`, `"Owner"`, 1)} {
		if _, err := inspect(context.Background(), []byte(body), archive, binary); err == nil {
			t.Fatal("malformed/case-folded provenance admitted")
		}
	}
}

func TestBoundedCatalogFileReader(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFixed(file, 3); err == nil {
		t.Fatal("oversized file admitted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFixed(link, 64); err == nil {
		t.Fatal("symlink admitted")
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFixed(fifo, 64); err == nil {
		t.Fatal("FIFO admitted")
	}
}
