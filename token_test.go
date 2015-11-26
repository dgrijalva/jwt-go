package jwt_test

import (
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestNewTokenWithGzipCompression(t *testing.T) {
	var token = jwt.New(jwt.SigningMethodHS256, jwt.CompressionGzip)

	token.Claims = map[string]interface{}{
		"claim1": "testvalue1",
		"claim2": 42,
	}

	var tokenString, err = token.SignedString([]byte("TEST KEY"))
	if err != nil {
		t.Errorf("Error signing gzip compressed claims: %s", err)
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Errorf("Token string has %d parts", len(parts))
	}
	if parts[1] != "H4sIAAAJbogA_6pWSs5JzMw1VLJSKkktLilLzClNNVTSgYgaKVmZGNUCAgAA__9vre6IIwAAAA" {
		t.Error("Token claims not encoded properly")
	}
}

func TestNewTokenWithWrongCompressionAlg(t *testing.T) {
	var token = jwt.New(jwt.SigningMethodHS256, jwt.CompressionNone)
	token.Header["cpr"] = "dummy" // set wrong compression method
	token.Claims = map[string]interface{}{
		"claim1": "testvalue1",
		"claim2": 42,
	}

	var _, err = token.SignedString([]byte("TEST KEY"))
	if err == nil {
		t.Errorf("Expected error")
	} else if err.Error() != "Compression method dummy not registered" {
		t.Errorf("Unexpected error description: %s", err.Error())
	}
}
