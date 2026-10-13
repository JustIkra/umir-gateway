package catalog

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"github.com/JustIkra/umir-gateway/internal/strictjson"
)

const Amendment = "umir-owner-profiles/0.1.0-unpublished"
const Path = "/owner-profile/v1"
const archivePath = "/usr/local/lib/umir/zoneinfo.zip"
const provenancePath = "/usr/local/lib/umir/catalog-provenance.json"
const configPath = "/run/umir-fixtures/config/config.json"
const ContractIdentity = "sha256:ee5ea052cf8239a40fdc3aba7c97c0a143260be284c390168a75c8afb7770460"

var fixtureSHA256 string

type FixtureBinding struct {
	FixtureSHA256           string `json:"fixtureSHA256"`
	ProfileContractIdentity string `json:"profileContractIdentity"`
}

const maxArchive = 16777216
const maxBinary = 64 << 20

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var projectPattern = regexp.MustCompile(`^umir-backend-[0-9a-f]{24}$`)
var generationPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

type Provenance struct {
	Owner                 string `json:"owner"`
	Version               string `json:"version"`
	ArchiveSHA256         string `json:"archiveSHA256"`
	ArchiveBytes          int    `json:"archiveBytes"`
	EmbeddedArchiveSHA256 string `json:"embeddedArchiveSHA256"`
	BuildToolchain        string `json:"buildToolchain"`
	ToolchainImageID      string `json:"toolchainImageID"`
	ToolchainSourceSHA256 string `json:"toolchainSourceSHA256"`
	BinarySHA256          string `json:"binarySHA256"`
	SourceKind            string `json:"sourceKind"`
}
type Fact struct {
	Owner            string `json:"owner"`
	Version          string `json:"version"`
	ArchiveSHA256    string `json:"archiveSHA256"`
	ArchiveBytes     int    `json:"archiveBytes"`
	BuildToolchain   string `json:"buildToolchain"`
	Ready            bool   `json:"ready"`
	ProvenanceSHA256 string `json:"provenanceSHA256"`
}
type ClockState struct {
	Instant    string `json:"instant"`
	Generation string `json:"generation"`
	InstanceID string `json:"instanceID"`
	Source     string `json:"source"`
	Healthy    bool   `json:"healthy"`
}
type Clock interface{ CatalogClock() ClockState }
type CatalogReport struct {
	Amendment    string     `json:"amendment"`
	RequestID    string     `json:"requestID"`
	Project      string     `json:"project"`
	InstanceID   string     `json:"instanceID"`
	Clock        ClockState `json:"clock"`
	BinarySHA256 string     `json:"binarySHA256"`
	ConfigSHA256 string     `json:"configSHA256"`
	Catalog      Fact       `json:"catalog"`
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func decode(data []byte, value any, fields int) error {
	if strictjson.CheckText(data) != nil {
		return errors.New("invalid JSON text")
	}
	object, err := strictjson.Object(data)
	if err != nil || len(object) != fields {
		return errors.New("invalid JSON fields")
	}
	model, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := checkShape(data, model); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value)
}
func readFixed(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	stat, statErr := f.Stat()
	if statErr != nil || !stat.Mode().IsRegular() || stat.Size() > limit || stat.Size() < 1 {
		return nil, errors.Join(errors.New("invalid catalog file"), statErr, f.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, errors.Join(errors.New("catalog file unavailable"), readErr, closeErr)
	}
	return data, nil
}
func inspect(ctx context.Context, manifest, archive, binary []byte) (Fact, error) {
	var p Provenance
	if ctx.Err() != nil {
		return Fact{}, ctx.Err()
	}
	if len(manifest) > 65536 || decode(manifest, &p, 10) != nil || p.Owner != "gateway" || p.Version != "go1.26.9-embedded" || p.BuildToolchain != "go1.26.9" || p.SourceKind != "go-time-tzdata" || !shaPattern.MatchString(p.ToolchainSourceSHA256) || len(p.ToolchainImageID) != 71 || p.ToolchainImageID[:7] != "sha256:" || !shaPattern.MatchString(p.ToolchainImageID[7:]) {
		return Fact{}, errors.New("invalid catalog provenance")
	}
	if len(archive) < 1 || len(archive) > maxArchive || p.ArchiveBytes != len(archive) || p.ArchiveSHA256 != digest(archive) || p.EmbeddedArchiveSHA256 != p.ArchiveSHA256 || p.BinarySHA256 != digest(binary) || !bytes.Contains(binary, archive) {
		return Fact{}, errors.New("catalog provenance mismatch")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(reader.File) > 4096 {
		return Fact{}, errors.New("invalid catalog archive")
	}
	found := false
	for _, f := range reader.File {
		if f.Name != "Europe/Moscow" {
			continue
		}
		if found || f.UncompressedSize64 > 1<<20 {
			return Fact{}, errors.New("invalid Moscow entry")
		}
		found = true
		r, err := f.Open()
		if err != nil {
			return Fact{}, err
		}
		data, readErr := io.ReadAll(io.LimitReader(r, 1<<20+1))
		closeErr := r.Close()
		if readErr != nil || closeErr != nil || len(data) > 1<<20 {
			return Fact{}, errors.Join(errors.New("invalid Moscow data"), readErr, closeErr)
		}
		if _, err := time.LoadLocationFromTZData("Europe/Moscow", data); err != nil {
			return Fact{}, err
		}
	}
	if !found {
		return Fact{}, errors.New("moscow timezone data is absent")
	}
	return Fact{Owner: p.Owner, Version: p.Version, ArchiveSHA256: p.ArchiveSHA256, ArchiveBytes: p.ArchiveBytes, BuildToolchain: p.BuildToolchain, Ready: true, ProvenanceSHA256: digest(manifest)}, nil
}
func Observe(ctx context.Context, clock Clock) (CatalogReport, error) {
	if clock == nil || runtime.Version() != "go1.26.9" || os.Getenv("ZONEINFO") != "" {
		return CatalogReport{}, errors.New("unqualified catalog runtime")
	}
	bindingData, err := readFixed("/usr/local/lib/umir/fixture-source.json", 65536)
	if err != nil {
		return CatalogReport{}, err
	}
	var binding FixtureBinding
	if decode(bindingData, &binding, 2) != nil || !shaPattern.MatchString(fixtureSHA256) || binding.FixtureSHA256 != fixtureSHA256 || binding.ProfileContractIdentity != ContractIdentity {
		return CatalogReport{}, errors.New("fixture source binding mismatch")
	}
	manifest, err := readFixed(provenancePath, 65536)
	if err != nil {
		return CatalogReport{}, err
	}
	archive, err := readFixed(archivePath, maxArchive)
	if err != nil {
		return CatalogReport{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return CatalogReport{}, err
	}
	binary, err := readFixed(executable, maxBinary)
	if err != nil {
		return CatalogReport{}, err
	}
	fact, err := inspect(ctx, manifest, archive, binary)
	if err != nil {
		return CatalogReport{}, err
	}
	config, err := readFixed(configPath, 1<<20)
	if err != nil {
		return CatalogReport{}, err
	}
	var input struct {
		Project string `json:"project"`
	}
	if json.Unmarshal(config, &input) != nil || !projectPattern.MatchString(input.Project) {
		return CatalogReport{}, errors.New("invalid catalog project")
	}
	state := clock.CatalogClock()
	if !state.Valid() {
		return CatalogReport{}, errors.New("unqualified catalog clock")
	}
	return CatalogReport{Amendment: Amendment, Project: input.Project, InstanceID: state.InstanceID, Clock: state, BinarySHA256: digest(binary), ConfigSHA256: digest(config), Catalog: fact}, nil
}
func (c ClockState) Valid() bool {
	instant, err := time.Parse(time.RFC3339Nano, c.Instant)
	return err == nil && c.Instant == instant.In(time.FixedZone("Europe/Moscow", 3*60*60)).Format(time.RFC3339Nano) && instant.Year() >= 2000 && instant.Year() <= 2099 && generationPattern.MatchString(c.Generation) && uuidPattern.MatchString(c.InstanceID) && c.Source == "owner" && c.Healthy
}

func checkShape(data, model []byte) error {
	actual, err := strictjson.Object(data)
	if err != nil {
		return err
	}
	expected, err := strictjson.Object(model)
	if err != nil || len(actual) != len(expected) {
		return errors.New("invalid JSON shape")
	}
	for key, reference := range expected {
		value, ok := actual[key]
		if !ok {
			return errors.New("incorrect field case or absent field")
		}
		if len(reference) > 0 && reference[0] == '{' {
			if err := checkShape(value, reference); err != nil {
				return err
			}
		}
	}
	return nil
}
