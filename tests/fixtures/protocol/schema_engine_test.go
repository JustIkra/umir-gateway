package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestAuthoritativeSchemaCases(t *testing.T) {
	data, err := os.ReadFile("testdata/authoritative-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		Name   string          `json:"name"`
		Schema string          `json:"schema"`
		Value  json.RawMessage `json:"value"`
	}
	var cases struct {
		SchemaSHA256 string     `json:"schemaSHA256"`
		Positive     []testCase `json:"positive"`
		Negative     []testCase `json:"negative"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if cases.SchemaSHA256 != SHA(schemaJSON) {
		t.Fatal("case source and snapshot differ")
	}
	for _, group := range []struct {
		cases []testCase
		valid bool
	}{{cases.Positive, true}, {cases.Negative, false}} {
		for _, tc := range group.cases {
			name := strings.TrimPrefix(tc.Schema, "#/$defs/")
			if err := validate(name, tc.Value); (err == nil) != group.valid {
				t.Errorf("%s %s valid=%v: %v", name, tc.Name, group.valid, err)
			}
		}
	}
}

func TestOwnerCredentialNameBoundaries(t *testing.T) {
	data, err := os.ReadFile("testdata/authoritative-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Positive []struct {
			Name  string
			Value Config
		}
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	for _, tc := range cases.Positive {
		if tc.Name == "gateway-owner-config" {
			cfg = tc.Value
		}
	}
	if cfg.Owner != "gateway" {
		t.Fatal("missing Gateway source case")
	}
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"gateway-auth", true}, {"auth-gateway", true}, {"gateway-warehouse", true}, {"gateway-serving", true}, {"gateway-feedback", true},
		{"fixture-gateway", false}, {"fixture-", false}, {"fixture-auth", false}, {"", false},
		{"gateway\nauth", false}, {"\ngateway-auth", false}, {"gateway-auth\n", false},
		{"gateway-auth\r", false}, {"gateway-auth\u2028", false}, {"gateway-auth\u2029", false},
		{"ключ", true}, {"🍽️", true}, {"Fixture-gateway", true}, {"fixture", true}, {"fixture‐gateway", true}, {"éfixture-gateway", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.CredentialFiles = map[string]FileRef{tc.name: {Target: "gateway", Path: "/run/umir-fixtures/secrets/gateway-auth"}}
			body, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := validate("OwnerConfig", body); (err == nil) != tc.valid {
				t.Fatalf("authoritative name predicate valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func probeValidator(t *testing.T, document string) *schemaValidator {
	t.Helper()
	v := &schemaValidator{schemas: map[string]*jsonschema.Schema{}}
	v.budget.reset(2 * time.Second)
	c := jsonschema.NewCompiler()
	c.UseRegexpEngine(v.budget.compile)
	c.AssertFormat()
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("probe.json", value); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("probe.json")
	if err != nil {
		t.Fatal(err)
	}
	v.schemas["probe"] = s
	return v
}

func TestMatchTimeoutCannotPassSchemaBranches(t *testing.T) {
	for _, schema := range []string{
		`{"not":{"pattern":"^(a+)+$"}}`,
		`{"anyOf":[{"pattern":"^(a+)+$"},true]}`,
		`{"oneOf":[{"pattern":"^(a+)+$"},true]}`,
		`{"if":{"pattern":"^(a+)+$"},"else":true}`,
		`{"propertyNames":{"not":{"pattern":"^(a+)+$"}}}`,
	} {
		v := probeValidator(t, schema)
		input := strings.Repeat("a", 10000) + "!"
		var value any = input
		if strings.Contains(schema, "propertyNames") {
			value = map[string]any{input: nil}
		}
		started := time.Now()
		err := v.validate("probe", value)
		var failure schemaMatchFailure
		if !errors.As(err, &failure) {
			t.Fatalf("match failure became branch acceptance/rejection: %v", err)
		}
		if time.Since(started) > 2*time.Second {
			t.Fatal("regex timeout was not bounded")
		}
		if err := v.validate("probe", 42); err != nil {
			var failure schemaMatchFailure
			if errors.As(err, &failure) {
				t.Fatalf("failed call poisoned the next admission: %v", err)
			}
		}
	}
}

func TestSchemaCompilationAndFormatFailures(t *testing.T) {
	invalid := bytes.Replace(schemaJSON, []byte("^(?!fixture-).+$"), []byte("("), 1)
	if _, err := compileFixtureSchemas(invalid); err == nil {
		t.Fatal("compilation error swallowed")
	}
	v := probeValidator(t, `{"type":"string","format":"date-time"}`)
	if err := v.validate("probe", "2026-02-30T09:00:00+03:00"); err == nil {
		t.Fatal("format assertion disabled")
	}
	if err := validate("clock_read_request", bytes.Repeat([]byte(" "), schemaInputLimit+1)); err == nil {
		t.Fatal("unbounded JSON input")
	}
}

func TestMatchWorkAndDeadlineFailure(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		b := &matchBudget{}
		b.reset(time.Second)
		re, err := b.compile("a")
		if err != nil {
			t.Fatal(err)
		}
		if deadline {
			b.deadline = time.Now().Add(-time.Second)
		} else {
			b.remaining = 0
		}
		func() {
			var err error
			func() { defer recoverSchemaMatch(&err); re.MatchString("a") }()
			var failure schemaMatchFailure
			if !errors.As(err, &failure) {
				t.Fatal("work limit swallowed", err)
			}
		}()
	}
}

func TestConcurrentSchemaBudgetsAreIsolated(t *testing.T) {
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			body := []byte(`{"version":1,"project":"` + testProject + `","requestID":"` + testID + `","operation":"clock.read","data":{}}`)
			for range 8 {
				if err := validate("clock_read_request", body); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

type runtimeFailureRegexp struct{ cause error }

func (r runtimeFailureRegexp) String() string          { return "a" }
func (r runtimeFailureRegexp) MatchString(string) bool { panic(schemaMatchFailure(r)) }

func TestRuntimeErrorCannotPassNegationOrAlternative(t *testing.T) {
	cause := errors.New("runtime match failure probe")
	for _, schema := range []string{`{"not":{"pattern":"a"}}`, `{"anyOf":[{"pattern":"a"},true]}`, `{"oneOf":[{"pattern":"a"},true]}`, `{"if":{"pattern":"a"},"else":true}`} {
		v := probeValidator(t, schema)
		s := v.schemas["probe"]
		var pattern *jsonschema.Schema
		switch {
		case s.Not != nil:
			pattern = s.Not
		case s.AnyOf != nil:
			pattern = s.AnyOf[0]
		case s.OneOf != nil:
			pattern = s.OneOf[0]
		default:
			pattern = s.If
		}
		pattern.Pattern = runtimeFailureRegexp{cause}
		if err := v.validate("probe", "a"); !errors.Is(err, cause) {
			t.Fatalf("runtime failure swallowed by a schema branch: %v", err)
		}
	}
}

func TestUnrelatedPanicIsNotConvertedToValidation(t *testing.T) {
	defer func() {
		if recover() != "unrelated" {
			t.Fatal("unexpected panic swallowed")
		}
	}()
	var err error
	func() { defer recoverSchemaMatch(&err); panic("unrelated") }()
}

func TestGatewayOwnerConfigKeepsExactServiceBindings(t *testing.T) {
	data, err := os.ReadFile("testdata/authoritative-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Positive []struct {
			Name  string
			Value Config
		}
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	var base Config
	for _, tc := range cases.Positive {
		if tc.Name == "gateway-owner-config" {
			base = tc.Value
		}
	}
	if base.Owner != "gateway" {
		t.Fatal("missing Gateway case")
	}
	for _, mutation := range []string{"valid", "missing-service", "control-as-service", "service-as-control", "extra-service", "foreign-target"} {
		t.Run(mutation, func(t *testing.T) {
			cfg := base
			cfg.CredentialFiles = make(map[string]FileRef)
			for key, ref := range base.CredentialFiles {
				cfg.CredentialFiles[key] = ref
			}
			switch mutation {
			case "missing-service":
				delete(cfg.CredentialFiles, "auth-gateway")
			case "control-as-service":
				cfg.CredentialFiles["gateway-auth"] = cfg.ControlCredentialFile
			case "service-as-control":
				cfg.ControlCredentialFile = cfg.CredentialFiles["gateway-auth"]
			case "extra-service":
				cfg.CredentialFiles["extra"] = cfg.CredentialFiles["gateway-auth"]
			case "foreign-target":
				cfg.CredentialFiles["gateway-auth"] = FileRef{Target: "auth", Path: "/run/umir-fixtures/secrets/gateway-auth"}
			}
			body, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := privateFileDir(t) + "/config.json"
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			_, digest, err := LoadConfig(path)
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("exact owner/service admission: %v", err)
			}
			if mutation == "valid" && digest != SHA(body) {
				t.Fatal("config identity changed")
			}
		})
	}
}

func TestWildcardDotUncertainty(t *testing.T) {
	for _, tc := range []struct {
		pattern  string
		wildcard bool
	}{{`\.`, false}, {`[.]`, false}, {`[\.]`, false}, {`^.+$`, true}, {`^a\..+$`, true}, {`[^.]`, false}} {
		if wildcardDot(tc.pattern) != tc.wildcard {
			t.Errorf("wildcard classification %s", tc.pattern)
		}
	}
	for _, schema := range []string{`{"not":{"pattern":"^.+$"}}`, `{"anyOf":[{"pattern":"^.+$"},true]}`} {
		v := probeValidator(t, schema)
		var failure schemaMatchFailure
		if err := v.validate("probe", "a\u2028"); !errors.As(err, &failure) {
			t.Fatalf("uncertain matching escaped as a branch result: %v", err)
		}
	}
	v := probeValidator(t, `{"pattern":"^[\\s]+$"}`)
	if err := v.validate("probe", "\u2028"); err != nil {
		t.Fatal("well-defined Unicode class rejected", err)
	}
}
