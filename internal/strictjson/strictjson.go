// Package strictjson finds JSON text that encoding/json would silently decode to U+FFFD.
package strictjson

import (
	"errors"
	"strconv"
	"unicode/utf8"
)

// ErrText reports invalid UTF-8 or an unpaired UTF-16 surrogate escape in a JSON document.
var ErrText = errors.New("JSON text has invalid UTF-8 or an unpaired surrogate escape")

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
