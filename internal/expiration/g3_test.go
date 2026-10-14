package expiration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/journal"
)

func TestG3RejectedWriteDoesNotHideExternalExpiration(t *testing.T) {
	h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){run("5", 0), run("6", 0), run("6", 0)}}), time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	signals := h.journal.Subscribe(ctx)
	h.runner.runOnce(ctx)
	h.journal.Append(journal.Entry{Source: journal.SourceRequest, Status: 409, Outcome: journal.OutcomeRejected})
	h.runner.runOnce(ctx)
	h.runner.runOnce(ctx)
	got := h.entries()
	if len(got) != 2 || got[1].Source != journal.SourceExternal || got[1].Outcome != journal.OutcomeUnknown {
		t.Fatalf("external expiration masked: %+v", got)
	}
	select {
	case <-signals:
	default:
		t.Fatal("no invalidation signal")
	}
	select {
	case <-signals:
		t.Fatal("duplicate signal")
	default:
	}
}

func TestG3MalformedExpirationIsUnknown(t *testing.T) {
	const at = `"2026-10-12T14:00:01+03:00"`
	valid := `{"evaluatedAt":` + at + `,"stateVersion":"5","expired":[]}`
	cases := map[string]string{
		"missing expired":     `{"evaluatedAt":` + at + `,"stateVersion":"5"}`,
		"null expired":        `{"evaluatedAt":` + at + `,"stateVersion":"5","expired":null}`,
		"missing evaluatedAt": `{"stateVersion":"5","expired":[]}`,
		"invalid evaluatedAt": strings.Replace(valid, "2026-10-12", "2026-02-30", 1),
		"non Moscow instant":  strings.Replace(valid, "+03:00", "Z", 1),
		"signed version":      strings.Replace(valid, `"5"`, `"+5"`, 1),
		"leading zero":        strings.Replace(valid, `"5"`, `"05"`, 1),
		"negative zero":       strings.Replace(valid, `"5"`, `"-0"`, 1),
		"overflow":            strings.Replace(valid, `"5"`, `"9223372036854775808"`, 1),
		"missing version":     `{"evaluatedAt":` + at + `,"expired":[]}`,
		"trailing value":      valid + ` {}`,
		"trailing bytes":      valid + `garbage`,
		"unknown field":       strings.TrimSuffix(valid, "}") + `,"extra":true}`,
		"incomplete item":     strings.Replace(valid, `[]`, `[{}]`, 1),
		"null item":           strings.Replace(valid, `[]`, `[null]`, 1),
		"oversized":           valid + strings.Repeat(" ", maxBody),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){answer(200, body)}}), time.Second)
			for range 3 {
				h.runner.runOnce(t.Context())
			}
			got := h.entries()
			if len(got) != 1 || got[0].Source != journal.SourceExpiration || got[0].Outcome != journal.OutcomeUnknown || got[0].Count != 0 {
				t.Fatalf("malformed response accepted: %+v", got)
			}
			if h.runner.known || len(h.upstream.changes()) != 1 || h.upstream.changes()[0] {
				t.Fatal("malformed response became healthy baseline")
			}
		})
	}
}

func TestG3CanonicalExpirationVersionControls(t *testing.T) {
	for _, v := range []string{"0", "9007199254740993", "9223372036854775807"} {
		t.Run(v, func(t *testing.T) {
			h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){run(v, 0)}}), time.Second)
			h.runner.runOnce(t.Context())
			if !h.runner.known || len(h.entries()) != 0 {
				t.Fatal("canonical response refused")
			}
		})
	}
}
