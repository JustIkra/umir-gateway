package operatorhttp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/JustIkra/umir-gateway/internal/strictjson"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed auth-contract.json
var authContractJSON []byte

type facadeParameter struct {
	Name      string          `json:"name"`
	In        string          `json:"in"`
	Required  bool            `json:"required"`
	Schema    json.RawMessage `json:"schema"`
	integer   bool
	validator *jsonschema.Schema
}

type FacadeOperation struct {
	Path       string            `json:"path"`
	Method     string            `json:"method"`
	Status     int               `json:"status"`
	Parameters []facadeParameter `json:"parameters"`
	Request    json.RawMessage   `json:"request"`
	Response   json.RawMessage   `json:"response"`
	id         string
	request    *jsonschema.Schema
	response   *jsonschema.Schema
}

type facadeContract struct {
	Operations map[string]*FacadeOperation `json:"operations"`
	failure    *jsonschema.Schema
}

var facadeOnce sync.Once
var facadeSchemas facadeContract
var facadeError error
var facadeEmail = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")

func loadFacade() (*facadeContract, error) {
	facadeOnce.Do(func() {
		if facadeError = json.Unmarshal(authContractJSON, &facadeSchemas); facadeError != nil {
			return
		}
		var value any
		value, facadeError = decodeFacade(authContractJSON)
		if facadeError != nil {
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.AssertFormat()
		compiler.RegisterFormat(&jsonschema.Format{Name: "email", Validate: func(value any) error {
			if text, ok := value.(string); ok && (len(text) > 254 || !facadeEmail.MatchString(text)) {
				return errors.New("invalid Auth email")
			}
			return nil
		}})
		const location = "urn:umir:gateway:auth-facade"
		if facadeError = compiler.AddResource(location, value); facadeError != nil {
			return
		}
		facadeSchemas.failure, facadeError = compiler.Compile(location + "#/components/schemas/Error")
		if facadeError != nil {
			return
		}
		for id, op := range facadeSchemas.Operations {
			op.id = id
			if len(op.Request) > 0 {
				op.request, facadeError = compiler.Compile(location + "#/operations/" + id + "/request")
				if facadeError != nil {
					return
				}
			}
			if len(op.Response) > 0 {
				op.response, facadeError = compiler.Compile(location + "#/operations/" + id + "/response")
				if facadeError != nil {
					return
				}
			}
			for i := range op.Parameters {
				var shape struct {
					Type string `json:"type"`
				}
				if facadeError = json.Unmarshal(op.Parameters[i].Schema, &shape); facadeError != nil {
					return
				}
				op.Parameters[i].integer = shape.Type == "integer"
				op.Parameters[i].validator, facadeError = compiler.Compile(fmt.Sprintf("%s#/operations/%s/parameters/%d/schema", location, id, i))
				if facadeError != nil {
					return
				}
			}
		}
	})
	return &facadeSchemas, facadeError
}

func decodeFacade(data []byte) (any, error) {
	if err := strictjson.CheckText(data); err != nil {
		return nil, err
	}
	if err := uniqueFacadeJSON(data, 0); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}

func uniqueFacadeJSON(data []byte, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return errors.New("missing JSON")
	}
	switch data[0] {
	case '{':
		fields, err := strictjson.Object(data)
		if err != nil {
			return err
		}
		for _, value := range fields {
			if err := uniqueFacadeJSON(value, depth+1); err != nil {
				return err
			}
		}
	case '[':
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := uniqueFacadeJSON(value, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func matchFacadePath(pattern, path string) (map[string]string, bool) {
	expected, actual := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(expected) != len(actual) {
		return nil, false
	}
	params := map[string]string{}
	for i, part := range expected {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			params[part[1:len(part)-1]] = actual[i]
		} else if part != actual[i] {
			return nil, false
		}
	}
	return params, true
}

func facadeRoute(method, path string) (*FacadeOperation, []string, error) {
	c, err := loadFacade()
	if err != nil {
		return nil, nil, err
	}
	var allowed []string
	var selected *FacadeOperation
	for _, op := range c.Operations {
		if _, matches := matchFacadePath(op.Path, path); matches {
			allowed = append(allowed, op.Method)
			if op.Method == http.MethodGet {
				allowed = append(allowed, http.MethodHead)
			}
			if op.Method == method {
				selected = op
			}
		}
	}
	slices.Sort(allowed)
	return selected, allowed, nil
}

func ValidateFacadeRequest(in FacadeRequest) (*FacadeOperation, error) {
	op, _, err := facadeRoute(in.Method, in.Path)
	if err != nil || op == nil {
		return nil, errors.New("unknown Auth operation")
	}
	params, _ := matchFacadePath(op.Path, in.Path)
	query, err := url.ParseQuery(in.RawQuery)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, p := range op.Parameters {
		values := []string{params[p.Name]}
		if p.In == "query" {
			known[p.Name] = true
			values = query[p.Name]
		}
		if len(values) == 0 && !p.Required {
			continue
		}
		if len(values) != 1 || !utf8.ValidString(values[0]) {
			return nil, errors.New("invalid Auth parameter")
		}
		var value any = values[0]
		if p.integer {
			n, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil || strconv.FormatInt(n, 10) != values[0] {
				return nil, errors.New("invalid Auth integer parameter")
			}
			value = json.Number(values[0])
		}
		if p.validator.Validate(value) != nil {
			return nil, errors.New("invalid Auth parameter")
		}
	}
	for key := range query {
		if !known[key] {
			return nil, errors.New("unknown Auth query")
		}
	}
	if op.request != nil {
		value, err := decodeFacade(in.Body)
		if err != nil {
			return nil, err
		}
		if err := op.request.Validate(value); err != nil {
			return nil, err
		}
		fields, err := strictjson.Object(in.Body)
		if err != nil {
			return nil, err
		}
		for key, expected := range params {
			if raw, present := fields[key]; present {
				var actual string
				if json.Unmarshal(raw, &actual) != nil || actual != expected {
					return nil, errors.New("auth path/body identity mismatch")
				}
			}
		}
	} else if len(in.Body) != 0 {
		return nil, errors.New("unexpected Auth body")
	}
	return op, nil
}

func (op *FacadeOperation) ValidateResponse(in FacadeRequest, data []byte) error {
	if op.response == nil {
		if len(bytes.TrimSpace(data)) != 0 {
			return errors.New("unexpected Auth result")
		}
		return nil
	}
	value, err := decodeFacade(data)
	if err != nil {
		return err
	}
	if err := op.response.Validate(value); err != nil {
		return err
	}
	params, _ := matchFacadePath(op.Path, in.Path)
	if op.id == "resendInvitationLink" {
		if err := matchFacadeIdentity(value, "resourceID", params["invitationID"]); err != nil {
			return err
		}
		var receipt struct {
			MailJobs []json.RawMessage `json:"mailJobs"`
		}
		if json.Unmarshal(data, &receipt) != nil || len(receipt.MailJobs) != 1 {
			return errors.New("invitation link receipt must contain one job")
		}
	}
	if op.id == "deleteRestaurant" {
		var result struct {
			RestaurantIDs []string `json:"restaurantIDs"`
		}
		if json.Unmarshal(data, &result) != nil || len(result.RestaurantIDs) != 1 || result.RestaurantIDs[0] != params["restaurantID"] {
			return errors.New("restaurant deletion identity mismatch")
		}
	}
	var input map[string]json.RawMessage
	if len(in.Body) != 0 {
		if err := json.Unmarshal(in.Body, &input); err != nil {
			return err
		}
	}
	query, err := url.ParseQuery(in.RawQuery)
	if err != nil {
		return err
	}
	for _, key := range []string{"commandID", "orgID", "membershipID", "invitationID", "challengeID", "operationID"} {
		expected := params[key]
		if key == "commandID" {
			expected = query.Get(key)
			if raw, ok := input[key]; ok {
				if err := json.Unmarshal(raw, &expected); err != nil {
					return err
				}
			}
		}
		if expected != "" {
			if err := matchFacadeIdentity(value, key, expected); err != nil {
				return err
			}
		}
	}
	return nil
}

func matchFacadeIdentity(value any, key, expected string) error {
	switch node := value.(type) {
	case map[string]any:
		for name, child := range node {
			if name == key && child != expected {
				return errors.New("auth response identity mismatch")
			}
			if err := matchFacadeIdentity(child, key, expected); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range node {
			if err := matchFacadeIdentity(child, key, expected); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateFacadeFailure(data []byte) error {
	c, err := loadFacade()
	if err != nil {
		return err
	}
	value, err := decodeFacade(data)
	if err != nil {
		return err
	}
	return c.failure.Validate(value)
}
