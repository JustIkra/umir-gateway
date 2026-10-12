package strictjson

import (
	"errors"
	"testing"
)

func TestCheckText(t *testing.T) {
	for _, valid := range []string{
		`{"name":"Оператор"}`,
		"{\"name\":\"Опе\xef\xbf\xbdратор\"}", // a literal U+FFFD is valid text
		`{"name":"Опе\ufffdратор"}`,
		`{"emoji":"\ud83d\ude00"}`, // a valid surrogate pair
		`{"emoji":"\uD83D\uDE00"}`, // upper-case hex
		`{"text":"\\ud800"}`,       // an escaped backslash followed by the letters ud800
		`{"text":"tab\tand\\"}`,
		`{"broken":"\u12"}`, // a malformed escape is left to the JSON decoder
	} {
		if err := CheckText([]byte(valid)); err != nil {
			t.Errorf("CheckText(%s) = %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"{\"name\":\"bad\xff\"}",
		`{"name":"Опе\ud800ратор"}`, // unpaired high surrogate
		`{"name":"\ud800\u0041"}`,   // high surrogate followed by a non-surrogate
		`{"name":"\ud800\ud800"}`,   // high surrogate followed by another high one
		`{"name":"\udc00"}`,         // unpaired low surrogate
		`{"name":"\uDFFF"}`,
		`"\ud800`, // high surrogate at the end of the data
	} {
		if err := CheckText([]byte(invalid)); !errors.Is(err, ErrText) {
			t.Errorf("CheckText(%s) = %v, want ErrText", invalid, err)
		}
	}
}
