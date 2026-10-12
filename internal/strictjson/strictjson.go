// Package strictjson rejects JSON that encoding/json would silently accept: text it would decode to U+FFFD
// and objects with duplicate keys.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

var (
	// ErrText reports invalid UTF-8 or an unpaired UTF-16 surrogate escape in a JSON document.
	ErrText = errors.New("JSON text has invalid UTF-8 or an unpaired surrogate escape")
	// ErrObject reports a document that is not exactly one JSON object with unique keys.
	ErrObject = errors.New("JSON document is not one object with unique keys")
)

// Object reads exactly one JSON object and returns its members by their exact keys. encoding/json would
// keep the last of duplicate keys, so duplicates are rejected, as is data after the object.
func Object(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrObject
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, isKey := token.(string)
		if err != nil || !isKey {
			return nil, ErrObject
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, ErrObject
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrObject
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrObject
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrObject
	}
	return fields, nil
}

// CheckText returns ErrText when data holds invalid UTF-8 or a \uD800-\uDFFF escape that is not part of
// a surrogate pair. encoding/json decodes both to U+FFFD, so the decoded value would differ from what
// was sent; a literal U+FFFD is valid text. Malformed escapes are left to the JSON decoder.
func CheckText(data []byte) error {
	if !utf8.Valid(data) {
		return ErrText
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++ // the escaped character, so an escaped backslash never starts an escape
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		r, ok := hex4(data, i+1)
		if !ok {
			continue
		}
		i += 4
		switch {
		case r >= 0xD800 && r <= 0xDBFF: // a high surrogate needs a low one right after it
			if i+6 < len(data) && data[i+1] == '\\' && data[i+2] == 'u' {
				if low, ok := hex4(data, i+3); ok && low >= 0xDC00 && low <= 0xDFFF {
					i += 6
					continue
				}
			}
			return ErrText
		case r >= 0xDC00 && r <= 0xDFFF:
			return ErrText
		}
	}
	return nil
}

// hex4 reads the four hex digits of a \u escape starting at at.
func hex4(data []byte, at int) (rune, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(data[at:at+4]), 16, 16)
	return rune(n), err == nil
}
