package jwt

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"
)

// TimeFunc provides the current time when parsing token to validate "exp" claim (expiration time).
// You can override it to use another time value.  This is useful for testing or if your
// server uses a different time zone than your tokens.
var TimeFunc = time.Now

// Parse methods use this callback function to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use properties in the
// Header of the token (such as `kid`) to identify which key to use.
type Keyfunc func(*Token) (interface{}, error)

// TokenOption configures how we construct the token.
type TokenOption func(*Token) error

// A JWT Token.  Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
type Token struct {
	Raw       string                 // The raw token.  Populated when you Parse a token
	Method    SigningMethod          // The signing method used or to be used
	Header    map[string]interface{} // The first segment of the token
	Claims    Claims                 // The second segment of the token
	Signature string                 // The third segment of the token.  Populated when you Parse a token
	Valid     bool                   // Is the token valid?  Populated when you Parse/Verify a token
}

func validateCompressionAlgorithm(algorithm string) error {
	if algorithm != "DEF" {
		return fmt.Errorf("unsupported compression algorithm: %v", algorithm)
	}

	return nil
}

func compress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)

	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Flush(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	unzipped, err := ioutil.ReadAll(gz)
	if err != nil {
		return nil, err
	}

	return unzipped, nil
}

// WithClaims specifies the claims to use with the new token
func WithClaims(claims Claims) TokenOption {
	return func(t *Token) error {
		t.Claims = claims
		return nil
	}
}

// WithCompression specifies the compression algorithm to use with the new token
func WithCompression(algorithm ...string) TokenOption {
	return func(t *Token) error {
		for _, a := range algorithm {
			if err := validateCompressionAlgorithm(a); err != nil {
				return err
			}
		}

		t.Header["zip"] = "DEF"
		return nil
	}
}

// WithSigningMethod specifies the signing method of the new token
func WithSigningMethod(method SigningMethod) TokenOption {
	return func(t *Token) error {
		t.Header["alg"] = method.Alg()
		t.Method = method
		return nil
	}
}

// NewWithOptions constructs a new token using the given options
func NewWithOptions(options ...TokenOption) (*Token, error) {
	t := &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
		},
	}

	for _, option := range options {
		err := option(t)
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}

// Create a new Token.  Takes a signing method
func New(method SigningMethod) *Token {
	t, _ := NewWithOptions(WithSigningMethod(method))
	return t
}

func NewWithClaims(method SigningMethod, claims Claims) *Token {
	t, _ := NewWithOptions(WithSigningMethod(method), WithClaims(claims))
	return t
}

// Get the complete, signed token
func (t *Token) SignedString(key interface{}) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.SigningString(); err != nil {
		return "", err
	}
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

// Generate the signing string.  This is the
// most expensive part of the whole deal.  Unless you
// need this for something special, just go straight for
// the SignedString.
func (t *Token) SigningString() (string, error) {
	var err error
	parts := make([]string, 2)
	for i, _ := range parts {
		var jsonValue []byte
		if i == 0 {
			if jsonValue, err = json.Marshal(t.Header); err != nil {
				return "", err
			}
		} else {
			if jsonValue, err = json.Marshal(t.Claims); err != nil {
				return "", err
			}

			if val, ok := t.Header["zip"].(string); ok {
				if err = validateCompressionAlgorithm(val); err != nil {
					return "", err
				}

				zipped, err := compress(jsonValue)
				if err != nil {
					return "", err
				}
				jsonValue = zipped
			}
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil
}

// Parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return new(Parser).Parse(tokenString, keyFunc)
}

func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	return new(Parser).ParseWithClaims(tokenString, claims, keyFunc)
}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
