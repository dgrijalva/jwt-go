package jwt

import (
	"strings"
	"testing"
)

var noneTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic none",
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.",
		"none",
		map[string]interface{}{"foo": "bar"},
		true,
	},
}

func TestNoneVerify(t *testing.T) {
	key := ""
	for _, data := range noneTestData {
		parts := strings.Split(data.tokenString, ".")

		method := GetSigningMethod(data.alg)
		err := method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestNoneSign(t *testing.T) {
	key := ""
	for _, data := range noneTestData {
		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			method := GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), key)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}
			if sig != parts[2] {
				t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", data.name, sig, parts[2])
			}
		}
	}
}
