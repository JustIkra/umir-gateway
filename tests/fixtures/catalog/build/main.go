package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/JustIkra/umir-gateway/tests/fixtures/catalog"
)

func sha(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func extract(source []byte) ([]byte, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "zzipdata.go", source, 0)
	if err != nil {
		return nil, err
	}
	if file.Name.Name != "tzdata" || len(file.Decls) != 1 {
		return nil, errors.New("unexpected tzdata AST")
	}
	decl, ok := file.Decls[0].(*ast.GenDecl)
	if !ok || decl.Tok != token.CONST || len(decl.Specs) != 1 {
		return nil, errors.New("unexpected tzdata constant")
	}
	spec, ok := decl.Specs[0].(*ast.ValueSpec)
	if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "zipdata" || len(spec.Values) != 1 {
		return nil, errors.New("zipdata absent")
	}
	literal, ok := spec.Values[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return nil, errors.New("unexpected zipdata layout")
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}
func build() error {
	if runtime.Version() != "go1.26.9" || len(os.Args) != 1 {
		return errors.New("unqualified build toolchain")
	}
	source, err := os.ReadFile(filepath.Join("/usr/local/go", "src/time/tzdata/zzipdata.go"))
	if err != nil {
		return err
	}
	embedded, err := extract(source)
	if err != nil {
		return err
	}
	archive, err := os.ReadFile(filepath.Join("/usr/local/go", "lib/time/zoneinfo.zip"))
	if err != nil {
		return err
	}
	if !bytes.Equal(embedded, archive) || len(archive) == 0 || len(archive) > 16777216 {
		return errors.New("embedded archive mismatch")
	}
	binary, err := os.ReadFile("/out/fixture-server")
	if err != nil {
		return err
	}
	info, err := buildinfo.ReadFile("/out/fixture-server")
	if err != nil || info.GoVersion != "go1.26.9" || !bytes.Contains(binary, embedded) {
		return errors.New("executable embedding mismatch")
	}
	p := catalog.Provenance{Owner: "gateway", Version: "go1.26.9-embedded", ArchiveSHA256: sha(archive), ArchiveBytes: len(archive), EmbeddedArchiveSHA256: sha(embedded), BuildToolchain: info.GoVersion, ToolchainImageID: "sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade", ToolchainSourceSHA256: sha(source), BinarySHA256: sha(binary), SourceKind: "go-time-tzdata"}
	manifest, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.WriteFile("/out/zoneinfo.zip", archive, 0444); err != nil {
		return err
	}
	return os.WriteFile("/out/catalog-provenance.json", manifest, 0444)
}
func main() {
	var err error
	if len(os.Args) == 2 && os.Args[1] == "fixture-manifest" {
		err = fixtureManifest()
	} else {
		err = build()
	}
	if err != nil {
		os.Exit(1)
	}
}

type sourceFile struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

func fixtureManifest() error {
	files := []sourceFile{}
	err := filepath.WalkDir("tests/fixtures", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("nonregular fixture source")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, sourceFile{Path: filepath.ToSlash(path), Mode: uint32(info.Mode().Perm()), SHA256: sha(data)})
		return nil
	})
	if err != nil {
		return err
	}
	data, err := json.Marshal(files)
	if err != nil {
		return err
	}
	hash := sha(data)
	binding, err := json.Marshal(catalog.FixtureBinding{FixtureSHA256: hash, ProfileContractIdentity: catalog.ContractIdentity})
	if err != nil {
		return err
	}
	if err := os.MkdirAll("/out", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("/out/fixture-source.json", binding, 0444); err != nil {
		return err
	}
	if err := os.WriteFile("/out/fixture-source-manifest.json", data, 0444); err != nil {
		return err
	}
	return os.WriteFile("/out/fixture-source.sha", []byte(hash), 0444)
}
