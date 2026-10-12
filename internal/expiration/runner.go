// Package expiration starts the warehouse's expiration runs, so write-offs by expiry pass through the
// gateway and its journal like every other change. The warehouse still decides what has expired.
package expiration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	// LastRequest is the seq of the newest request entry, 0 before the first.
	LastRequest() int64
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
	// version and requests are the warehouse state version and LastRequest after the previous successful
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
	StateVersion string            `json:"stateVersion"`
	Expired      []json.RawMessage `json:"expired"`
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
	var result runResult
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return runResult{}, fmt.Errorf("decode run: %w", err)
	}
	return result, nil
}

func (r *Runner) succeeded(result runResult) {
	version, err := strconv.ParseInt(result.StateVersion, 10, 64)
	if err != nil || version < 0 {
		r.failed(http.StatusOK, true, fmt.Errorf("stateVersion %q", result.StateVersion))
		return
	}
	requests := r.opts.Journal.LastRequest()
	switch {
	case len(result.Expired) > 0:
		r.opts.Journal.Append(journal.Entry{
			Source: journal.SourceExpiration, Status: http.StatusOK, Outcome: journal.OutcomeSuccess, Count: len(result.Expired),
		})
	case r.known && version != r.version && requests == r.requests:
		// The state moved, yet no request passed the gateway since the previous run: a fresh warehouse
		// operation wrote off an expired batch inside a read, or the warehouse restarted.
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
