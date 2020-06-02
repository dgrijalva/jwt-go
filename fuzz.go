package jwt

import (
	"crypto/rsa"
)

var (
	jwtTestDefaultKey *rsa.PublicKey
	defaultKeyFunc    Keyfunc = func(t *Token) (interface{}, error) { return jwtTestDefaultKey, nil }
)

func Fuzz(data []byte) int {
	parser := Parser{UseJSONNumber: true}
	_, err := parser.Parse(string(data), defaultKeyFunc)
	if err != nil {
		return 0
	}
	return 1
}
