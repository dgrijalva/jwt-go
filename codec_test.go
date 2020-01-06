package jwt_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/dgrijalva/jwt-go/v4/test"
)

func TestCustomCodec(t *testing.T) {
	var customEncoderUsed = false
	var encoder = func(f jwt.FieldDescriptor, v interface{}) ([]byte, error) {
		customEncoderUsed = true
		if f == jwt.HeadFieldDescriptor {
			return json.Marshal(v)
		}

		// encode as some random bytes
		return []byte("abc123"), nil
	}
	var customDecoderUsed = false
	var decoder = func(f jwt.FieldDescriptor, data []byte, v interface{}) error {
		customDecoderUsed = true
		if f == jwt.HeadFieldDescriptor {
			return json.Unmarshal(data, v)
		}

		// Ensure the value was encoded using the custom marshaler
		if x := "abc123"; !bytes.Equal(data, []byte(x)) {
			t.Errorf("Encoded data %v didn't match expectation %v", string(data), string(x))
		}

		// Parse it as if it were encoded correctly
		return json.Unmarshal([]byte(`{"foo": "bar"}`), v)
	}
	privateKey := test.LoadRSAPrivateKeyFromDisk("test/sample_key")
	publicKey := privateKey.Public()

	// Create and encode a token
	var token = jwt.New(jwt.SigningMethodRS256)
	token.Claims = jwt.MapClaims{"foo": "bar"}
	tokenString, err := token.SignedString(privateKey, jwt.WithMarshaller(encoder))
	if err != nil {
		t.Fatalf("Unexpected error when encoding: %v", err)
	}
	if !customEncoderUsed {
		t.Error("Custom encoder was not used as expected")
	}

	// Decode the token
	parsedToken, err := jwt.Parse(tokenString, jwt.KnownKeyfunc(jwt.SigningMethodRS256, publicKey), jwt.WithUnmarshaller(decoder))
	if err != nil {
		t.Fatalf("Unexpected error when encoding: %v", err)
	}
	if !customDecoderUsed {
		t.Error("Custom encoder was not used as expected")
	}
	if !reflect.DeepEqual(token.Claims, parsedToken.Claims) {
		t.Errorf("Parsed token %v didn't match expectation %v", parsedToken.Claims, token.Claims)
	}

}
