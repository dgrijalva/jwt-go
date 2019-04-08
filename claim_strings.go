package jwt

import (
	"encoding/json"
	"reflect"
)

// ClaimStrings is used for parsing claim properties that
// can be either a string or array of strings
type ClaimStrings []string

// UnmarshalJSON implements the json package's Unmarshaler interface
func (c *ClaimStrings) UnmarshalJSON(data []byte) error {
	var value interface{}
	err := json.Unmarshal(data, &value)
	if err != nil {
		return err
	}
	switch v := value.(type) {
	case string:
		*c = ClaimStrings{v}
	case []interface{}:
		result := make(ClaimStrings, 0, len(v))
		for i, vv := range v {
			if x, ok := vv.(string); ok {
				result = append(result, x)
			} else {
				return &json.UnsupportedTypeError{Type: reflect.TypeOf(v[i])}
			}
		}
		*c = result
	case nil:
	default:
		return &json.UnsupportedTypeError{Type: reflect.TypeOf(v)}
	}
	return nil
}
