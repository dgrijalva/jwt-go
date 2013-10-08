package jwt

import (
	"strings"
	"testing"
)

var sha256TestData = []struct {
	name        string
	tokenString string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"web sample",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		true,
	},
	{
		"web sample: invalid",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXo",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		false,
	},
}

// Sample data from http://tools.ietf.org/html/draft-jones-json-web-signature-04#appendix-A.1
var sha256TestKey = []byte{
	3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
	143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
	46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
	98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
	208, 128, 163}

func TestHS256Verify(t *testing.T) {
	for _, data := range sha256TestData {
		parts := strings.Split(data.tokenString, ".")

		method := GetSigningMethod("HS256")
		err := method.Verify(strings.Join(parts[0:2], "."), parts[2], sha256TestKey)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestHS256Sign(t *testing.T) {
	for _, data := range sha256TestData {
		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			method := GetSigningMethod("HS256")
			sig, err := method.Sign(strings.Join(parts[0:2], "."), sha256TestKey)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}
			if sig != parts[2] {
				t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", data.name, sig, parts[2])
			}
		}
	}
}
