package jwt_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dgrijalva/jwt-go/v4"
)

var claimStringsTestData = []struct {
	name   string
	input  interface{}
	output jwt.ClaimStrings
	err    error
}{
	{
		name:   "null",
		input:  nil,
		output: nil,
	},
	{
		name:   "single",
		input:  "foo",
		output: jwt.ClaimStrings{"foo"},
	},
	{
		name:   "multi",
		input:  []string{"foo", "bar"},
		output: jwt.ClaimStrings{"foo", "bar"},
	},
	{
		name:   "invalid",
		input:  float64(42),
		output: nil,
		err:    &json.UnsupportedTypeError{Type: reflect.TypeOf(float64(42))},
	},
	{
		name:   "invalid multi",
		input:  []interface{}{"foo", float64(42)},
		output: nil,
		err:    &json.UnsupportedTypeError{Type: reflect.TypeOf(float64(42))},
	},
}

func TestClaimStrings(t *testing.T) {
	for _, test := range claimStringsTestData {
		var r *struct {
			Value jwt.ClaimStrings `json:"value"`
		}
		data, _ := json.Marshal(map[string]interface{}{"value": test.input})
		err := json.Unmarshal(data, &r)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("[%v] Error didn't match expectation: %v != %v", test.name, test.err, err)
		}
		if !reflect.DeepEqual(test.output, r.Value) {
			t.Errorf("[%v] Unmarshaled value didn't match expectation: %v != %v", test.name, test.output, r.Value)
		}
	}
}
