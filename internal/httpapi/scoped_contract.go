package httpapi

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/JustIkra/umir-gateway/internal/strictjson"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed scoped-contract.json
var scopedContract []byte

type scopeParameter struct {
	Name      string          `json:"name"`
	In        string          `json:"in"`
	Required  bool            `json:"required"`
	Schema    json.RawMessage `json:"schema"`
	validator *jsonschema.Schema
	array     bool
	integer   bool
}

type scopeOperation struct {
	Path              string           `json:"path"`
	Method            string           `json:"method"`
	Capability        string           `json:"capability"`
	Owner             string           `json:"owner"`
	Parameters        []scopeParameter `json:"parameters"`
	Request           json.RawMessage  `json:"request"`
	Response          json.RawMessage  `json:"response"`
	id                string
	requestValidator  *jsonschema.Schema
	responseValidator *jsonschema.Schema
}

type scopeContract struct {
	Operations map[string]*scopeOperation `json:"operations"`
	validators map[string]*jsonschema.Schema
}

var loadScopedOnce sync.Once
var loadedScoped *scopeContract
var loadScopedError error

func contract() (*scopeContract, error) {
	loadScopedOnce.Do(func() { loadedScoped, loadScopedError = compileScoped() })
	return loadedScoped, loadScopedError
}

func compileScoped() (*scopeContract, error) {
	var result scopeContract
	if err := json.Unmarshal(scopedContract, &result); err != nil {
		return nil, err
	}
	doc, err := decodeScoped(scopedContract)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	const location = "urn:umir:gateway:scoped-contract"
	if err := c.AddResource(location, doc); err != nil {
		return nil, err
	}
	result.validators = map[string]*jsonschema.Schema{}
	var root struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(scopedContract, &root); err != nil {
		return nil, err
	}
	for name := range root.Components.Schemas {
		validator, err := c.Compile(location + "#/components/schemas/" + name)
		if err != nil {
			return nil, err
		}
		result.validators[name] = validator
	}
	for id, op := range result.Operations {
		op.id = id
		if len(op.Request) > 0 {
			op.requestValidator, err = c.Compile(location + "#/operations/" + id + "/request")
			if err != nil {
				return nil, err
			}
		}
		op.responseValidator, err = c.Compile(location + "#/operations/" + id + "/response")
		if err != nil {
			return nil, err
		}
		for i := range op.Parameters {
			p := &op.Parameters[i]
			p.validator, err = c.Compile(fmt.Sprintf("%s#/operations/%s/parameters/%d/schema", location, id, i))
			if err != nil {
				return nil, err
			}
			var scalar struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(p.Schema, &scalar); err != nil {
				return nil, err
			}
			p.array = scalar.Type == "array"
			p.integer = scalar.Type == "integer"
		}
	}
	return &result, nil
}

func decodeScoped(data []byte) (any, error) {
	if err := strictjson.CheckText(data); err != nil {
		return nil, err
	}
	if err := checkScopedJSON(data, 0); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}

func checkScopedJSON(data []byte, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return errors.New("missing JSON value")
	}
	switch data[0] {
	case '{':
		fields, err := strictjson.Object(data)
		if err != nil {
			return err
		}
		for _, v := range fields {
			if err := checkScopedJSON(v, depth+1); err != nil {
				return err
			}
		}
	case '[':
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		for _, v := range values {
			if err := checkScopedJSON(v, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateScopeWire(name string, data []byte) error {
	c, err := contract()
	if err != nil {
		return err
	}
	v, err := decodeScoped(data)
	if err != nil {
		return err
	}
	validator := c.validators[name]
	if validator == nil {
		return errors.New("unknown scoped schema")
	}
	return validator.Validate(v)
}

func (op *scopeOperation) validateInput(r *http.Request, body []byte, tenant string) (url.Values, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	for key, values := range query {
		if !utf8.ValidString(key) {
			return nil, errors.New("invalid query text")
		}
		for _, value := range values {
			if !utf8.ValidString(value) {
				return nil, errors.New("invalid query text")
			}
		}
	}
	known := map[string]bool{}
	pathValues, ok := op.pathParameters(r.URL)
	if !ok {
		return nil, errors.New("invalid route parameters")
	}
	for _, p := range op.Parameters {
		var values []string
		switch p.In {
		case "path":
			value := pathValues[p.Name]
			if (p.Name == "restaurantID" || p.Name == "orgID") && value != tenant {
				return nil, errors.New("scope parameter mismatch")
			}
			values = []string{value}
		case "query":
			known[p.Name] = true
			values = query[p.Name]
		case "header":
			values = r.Header.Values(p.Name)
		}
		if len(values) == 0 {
			if p.Required {
				return nil, errors.New("missing parameter")
			}
			continue
		}
		var value any
		if p.array {
			list := make([]any, len(values))
			for i, v := range values {
				list[i] = v
			}
			value = list
		} else {
			if len(values) != 1 {
				return nil, errors.New("duplicate parameter")
			}
			value = values[0]
			if p.integer {
				n, err := strconv.ParseInt(values[0], 10, 64)
				if err != nil || strconv.FormatInt(n, 10) != values[0] {
					return nil, errors.New("invalid integer")
				}
				value = json.Number(values[0])
			}
		}
		if err := p.validator.Validate(value); err != nil {
			return nil, err
		}
	}
	for k := range query {
		if !known[k] {
			return nil, errors.New("unknown query parameter")
		}
	}
	if r.URL.ForceQuery && r.URL.RawQuery == "" {
		return nil, errors.New("empty query")
	}
	if op.requestValidator != nil {
		value, err := decodeScoped(body)
		if err != nil {
			return nil, err
		}
		if err := op.requestValidator.Validate(value); err != nil {
			return nil, err
		}
	} else if len(bytes.TrimSpace(body)) > 0 {
		return nil, errors.New("unexpected body")
	}
	return query, nil
}

func (op *scopeOperation) audiences() []string {
	if op.Owner == "serving" {
		return []string{"umir-serving", "umir-warehouse"}
	}
	return []string{"umir-" + op.Owner}
}

func (c *scopeContract) match(method, path string) (*scopeOperation, string) {
	for _, op := range c.Operations {
		if op.Method != method {
			continue
		}
		if values, ok := scopePathParameters(op.Path, path); ok {
			id := values["restaurantID"]
			if id == "" {
				id = values["orgID"]
			}
			return op, id
		}
	}
	return nil, ""
}

func scopePathParameters(pattern, path string) (map[string]string, bool) {
	parts, actual := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(parts) != len(actual) {
		return nil, false
	}
	values := map[string]string{}
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if actual[i] == "" || actual[i] == "." || actual[i] == ".." || !utf8.ValidString(actual[i]) || strings.ContainsAny(actual[i], "\x00\r\n") {
				return nil, false
			}
			values[strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")] = actual[i]
		} else if part != actual[i] {
			return nil, false
		}
	}
	return values, true
}

func (op *scopeOperation) pathParameters(target *url.URL) (map[string]string, bool) {
	if op.id != "productBatches" {
		return scopePathParameters(op.Path, target.Path)
	}
	values, ok := scopePathParameters(op.Path, target.EscapedPath())
	if !ok {
		return nil, false
	}
	encoded := values["productID"]
	product, err := url.PathUnescape(encoded)
	if err != nil || encoded != url.PathEscape(product) || product == "." || product == ".." || !utf8.ValidString(product) || strings.ContainsAny(product, "/\x00\r\n") {
		return nil, false
	}
	values["productID"] = product
	return values, true
}
