// Package expiration starts the warehouse's expiration runs, so write-offs by expiry pass through the
// gateway and its journal like every other change. The warehouse still decides what has expired.
package expiration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/JustIkra/umir-gateway/internal/journal"
)

// failuresBeforeUnavailable failed runs in a row make the warehouse unavailable for the streams.
const failuresBeforeUnavailable = 3

// maxBody bounds the run response the gateway reads.
const maxBody = 1 << 20

// Journal is where the runs leave their entries.
type Journal interface {
	Append(journal.Entry) int64
	// LastSignalledRequest is the seq of the newest request entry that signalled a possible change, 0 before the first.
	LastSignalledRequest() int64
}

// Upstream learns whether the warehouse answers.
type Upstream interface {
	Set(available bool)
}

// Options are the runner's dependencies; every field is required.
type Options struct {
	Client *http.Client
	// Warehouse is the public warehouse address; the runs go to its /expiration-runs.
	Warehouse *url.URL
	Interval  time.Duration
	// Timeout bounds one run, as UPSTREAM_TIMEOUT bounds a proxied request.
	Timeout  time.Duration
	Journal  Journal
	Upstream Upstream
	// NewTicker paces the runs; tests replace it.
	NewTicker func(time.Duration) (<-chan time.Time, func())
	Logger    *log.Logger
}

// Runner starts one run at a time. It is owned by the process, which runs Run until shutdown.
type Runner struct {
	opts   Options
	target string

	// The fields below belong to the Run goroutine.
	failures int
	// reported is set after a failed run that may have changed state left its entry; later failures in
	// the same row add none, so an unreachable warehouse does not signal every second.
	reported bool
	// version and requests are the warehouse state version and LastSignalledRequest after the previous successful
	// run; known is false before it.
	version  int64
	requests int64
	known    bool
}

// New checks opts.
func New(opts Options) (*Runner, error) {
	if opts.Client == nil || opts.Warehouse == nil || opts.Interval <= 0 || opts.Timeout <= 0 || opts.Journal == nil ||
		opts.Upstream == nil || opts.NewTicker == nil || opts.Logger == nil {
		return nil, errors.New("expiration: client, warehouse, positive interval and timeout, journal, upstream, ticker and logger are required")
	}
	return &Runner{opts: opts, target: opts.Warehouse.JoinPath("expiration-runs").String()}, nil
}

// Run starts a run on every tick until ctx ends. A slow run delays the next one; runs never overlap.
func (r *Runner) Run(ctx context.Context) {
	ticks, stop := r.opts.NewTicker(r.opts.Interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			r.runOnce(ctx)
		}
	}
}

// runResult is the part of the warehouse answer the gateway reads.
type runResult struct {
	EvaluatedAt  string          `json:"evaluatedAt"`
	StateVersion string          `json:"stateVersion"`
	Expired      []expiredResult `json:"expired"`
}

type expiredResult struct {
	BatchID            string `json:"batchID"`
	ProductID          string `json:"productID"`
	WrittenOffQuantity string `json:"writtenOffQuantity"`
	Reason             string `json:"reason"`
	ExpiresAt          string `json:"expiresAt"`
	ProcessedAt        string `json:"processedAt"`
}

var decimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
var moscowInstant = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?\+03:00$`)

func validVersion(s string) bool {
	if !decimal.MatchString(s) {
		return false
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

func validInstant(s string) bool {
	if !moscowInstant.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func (r runResult) valid() bool {
	if !validInstant(r.EvaluatedAt) || !validVersion(r.StateVersion) || r.Expired == nil {
		return false
	}
	for _, e := range r.Expired {
		if e.BatchID == "" || e.ProductID == "" || !validVersion(e.WrittenOffQuantity) || e.WrittenOffQuantity == "0" ||
			e.Reason != "EXPIRATION" || !validInstant(e.ExpiresAt) || !validInstant(e.ProcessedAt) {
			return false
		}
	}
	return true
}

func (r *Runner) runOnce(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, r.opts.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.target, nil)
	if err != nil {
		r.failed(0, false, err)
		return
	}
	request.Header.Set("Accept", "application/json")
	response, err := r.opts.Client.Do(request)
	if err != nil {
		if parent.Err() != nil {
			return
		}
		// A refused connection sent nothing; any later failure may follow a recorded run.
		r.failed(0, !dialFailed(err), err)
		return
	}
	result, err := read(response)
	err = errors.Join(err, response.Body.Close())
	switch {
	case err != nil:
		r.failed(response.StatusCode, true, err)
	case response.StatusCode != http.StatusOK:
		r.failed(response.StatusCode, response.StatusCode >= http.StatusInternalServerError, fmt.Errorf("status %d", response.StatusCode))
	default:
		r.succeeded(result)
	}
}

// read decodes a 200 answer and drains any other, so the connection can be reused.
func read(response *http.Response) (runResult, error) {
	body := io.LimitReader(response.Body, maxBody)
	if response.StatusCode != http.StatusOK {
		_, err := io.Copy(io.Discard, body)
		return runResult{}, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return runResult{}, fmt.Errorf("read run: %w", err)
	}
	if len(data) > maxBody {
		return runResult{}, errors.New("expiration response exceeds limit")
	}
	var result runResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return runResult{}, fmt.Errorf("decode run: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return runResult{}, errors.New("trailing expiration response data")
	}
	if !result.valid() {
		return runResult{}, errors.New("invalid expiration response envelope")
	}
	return result, nil
}

func (r *Runner) succeeded(result runResult) {
	version, err := strconv.ParseInt(result.StateVersion, 10, 64)
	if err != nil || version < 0 {
		r.failed(http.StatusOK, true, fmt.Errorf("stateVersion %q", result.StateVersion))
		return
	}
	requests := r.opts.Journal.LastSignalledRequest()
	switch {
	case len(result.Expired) > 0:
		r.opts.Journal.Append(journal.Entry{
			Source: journal.SourceExpiration, Status: http.StatusOK, Outcome: journal.OutcomeSuccess, Count: len(result.Expired),
		})
	case r.known && version != r.version && requests == r.requests:
		// Rejected requests cannot account for a change: they send no invalidation.
		r.opts.Journal.Append(journal.Entry{Source: journal.SourceExternal, Outcome: journal.OutcomeUnknown})
	}
	if r.failures >= failuresBeforeUnavailable {
		r.opts.Logger.Printf("expiration runs recovered after %d failures", r.failures)
	}
	r.version, r.requests, r.known = version, requests, true
	r.failures, r.reported = 0, false
	r.opts.Upstream.Set(true)
}

// failed counts a run without a usable answer. status is 0 without a response; mayHaveChanged says
// whether the warehouse may have recorded the run.
func (r *Runner) failed(status int, mayHaveChanged bool, cause error) {
	r.failures++
	if mayHaveChanged && !r.reported {
		r.opts.Journal.Append(journal.Entry{Source: journal.SourceExpiration, Status: status, Outcome: journal.OutcomeUnknown})
		r.reported = true
	}
	// The first failure and the switch to unavailable are logged; an outage does not log every second.
	switch r.failures {
	case 1:
		r.opts.Logger.Printf("expiration run failed: %v", cause)
	case failuresBeforeUnavailable:
		r.opts.Upstream.Set(false)
		r.opts.Logger.Printf("expiration runs failed %d times in a row; warehouse marked unavailable: %v", r.failures, cause)
	}
}

// dialFailed reports a request that never reached the warehouse.
func dialFailed(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
