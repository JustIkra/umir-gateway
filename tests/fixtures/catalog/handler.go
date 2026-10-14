package catalog

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

type Request struct {
	Amendment          string `json:"amendment"`
	Project            string `json:"project"`
	RequestID          string `json:"requestID"`
	ExpectedInstanceID string `json:"expectedInstanceID"`
	ExpectedGeneration string `json:"expectedGeneration"`
	Action             string `json:"action"`
}
type ProfileError struct {
	Amendment string `json:"amendment"`
	RequestID string `json:"requestID"`
	Error     string `json:"error"`
}
type Options struct {
	Project, Credential, BinarySHA256, ConfigSHA256 string
	Clock                                           Clock
	Ready                                           func(context.Context) bool
	Observe                                         func(context.Context, Clock) (CatalogReport, error)
}
type entry struct {
	request Request
	body    []byte
	status  int
}
type Handler struct {
	opts  Options
	mu    sync.Mutex
	cache map[string]entry
}

func NewHandler(opts Options) (*Handler, error) {
	if !projectPattern.MatchString(opts.Project) || !shaPattern.MatchString(opts.Credential) || !shaPattern.MatchString(opts.BinarySHA256) || !shaPattern.MatchString(opts.ConfigSHA256) || opts.Clock == nil || opts.Ready == nil || opts.Observe == nil {
		return nil, errors.New("invalid catalog dependencies")
	}
	return &Handler{opts: opts, cache: map[string]entry{}}, nil
}
func write(w http.ResponseWriter, body []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		return
	}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := "00000000-0000-4000-8000-000000000000"
	fail := func(code string, status int) {
		body, err := json.Marshal(ProfileError{Amendment: Amendment, RequestID: id, Error: code})
		if err != nil {
			w.WriteHeader(503)
			return
		}
		write(w, body, status)
	}
	if r.Method != http.MethodPost || r.URL.Path != Path || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		fail("InvalidRequest", 400)
		return
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || subtle.ConstantTimeCompare([]byte(auth[0]), []byte("Bearer "+h.opts.Credential)) != 1 {
		fail("Unauthorized", 401)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		fail("InvalidRequest", 400)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if err != nil {
		fail("InvalidRequest", 400)
		return
	}
	var input Request
	if decode(body, &input, 6) != nil || input.Amendment != Amendment || input.Action != "catalog-report" || !projectPattern.MatchString(input.Project) || !uuidPattern.MatchString(input.RequestID) || !uuidPattern.MatchString(input.ExpectedInstanceID) || !generationPattern.MatchString(input.ExpectedGeneration) {
		fail("InvalidRequest", 400)
		return
	}
	id = input.RequestID
	if input.Project != h.opts.Project {
		fail("OwnershipMismatch", 403)
		return
	}
	if !h.mu.TryLock() {
		fail("RequestConflict", 409)
		return
	}
	defer h.mu.Unlock()
	if cached, ok := h.cache[id]; ok {
		if cached.request != input {
			fail("RequestConflict", 409)
			return
		}
		write(w, cached.body, cached.status)
		return
	}
	if len(h.cache) >= 64 {
		fail("ProfileCapacityExceeded", 413)
		return
	}
	state := h.opts.Clock.CatalogClock()
	if !state.Valid() || state.InstanceID != input.ExpectedInstanceID || state.Generation != input.ExpectedGeneration {
		fail("ClockConflict", 409)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.opts.Ready(ctx) {
		fail("ProfileAdmissionFailed", 503)
		return
	}
	report, err := h.opts.Observe(ctx, h.opts.Clock)
	if err != nil || !report.Valid() || report.Project != input.Project || report.InstanceID != state.InstanceID || report.Clock != state || report.BinarySHA256 != h.opts.BinarySHA256 || report.ConfigSHA256 != h.opts.ConfigSHA256 {
		fail("ProfileAdmissionFailed", 503)
		return
	}
	if h.opts.Clock.CatalogClock() != state {
		fail("ClockConflict", 409)
		return
	}
	if ctx.Err() != nil {
		fail("ProfileExpired", 503)
		return
	}
	report.RequestID = id
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > 65536 {
		fail("ProfileAdmissionFailed", 503)
		return
	}
	h.cache[id] = entry{request: input, body: bytes.Clone(encoded), status: 200}
	write(w, encoded, 200)
}
func (r CatalogReport) Valid() bool {
	return r.Amendment == Amendment && projectPattern.MatchString(r.Project) && r.Clock.Valid() && r.InstanceID == r.Clock.InstanceID && shaPattern.MatchString(r.BinarySHA256) && shaPattern.MatchString(r.ConfigSHA256) && r.Catalog.Owner == "gateway" && r.Catalog.Version == "go1.26.9-embedded" && r.Catalog.BuildToolchain == "go1.26.9" && r.Catalog.Ready && r.Catalog.ArchiveBytes > 0 && r.Catalog.ArchiveBytes <= maxArchive && shaPattern.MatchString(r.Catalog.ArchiveSHA256) && shaPattern.MatchString(r.Catalog.ProvenanceSHA256)
}
func ValidateRequest(body []byte) (Request, error) {
	var r Request
	if len(body) > 65536 || decode(body, &r, 6) != nil || r.Amendment != Amendment || r.Action != "catalog-report" || !projectPattern.MatchString(r.Project) || !uuidPattern.MatchString(r.RequestID) || !uuidPattern.MatchString(r.ExpectedInstanceID) || !generationPattern.MatchString(r.ExpectedGeneration) {
		return Request{}, errors.New("invalid catalog request")
	}
	return r, nil
}
func ValidateReply(body []byte, request Request, status int) error {
	if status == 200 {
		var report CatalogReport
		if decode(body, &report, 8) != nil || !report.Valid() || report.Project != request.Project || report.RequestID != request.RequestID || report.InstanceID != request.ExpectedInstanceID || report.Clock.Generation != request.ExpectedGeneration {
			return errors.New("invalid catalog report")
		}
		return nil
	}
	var failure ProfileError
	if decode(body, &failure, 3) != nil || failure.Amendment != Amendment || failure.RequestID != request.RequestID {
		return errors.New("invalid profile error")
	}
	expected := map[string]int{"InvalidRequest": 400, "Unauthorized": 401, "RequestConflict": 409, "ClockConflict": 409, "OwnershipMismatch": 403, "UnsupportedOwnerProfile": 404, "UnsupportedAction": 404, "ProfileAdmissionFailed": 503, "ProfileExpired": 503, "ProfileCapacityExceeded": 413, "CheckpointFailed": 503}
	if expected[failure.Error] != status {
		return errors.New("invalid profile status")
	}
	return nil
}
