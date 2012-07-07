package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Parse methods use this callback function to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use propries in the
// Header of the token (such as `kid`) to identify which key to use.
type Keyfunc func(*Token) ([]byte, error)

// A JWT Token
type Token struct {
	Header map[string]interface{}
	Claims map[string]interface{}
	Method SigningMethod
	// This is only populated when you Parse a token
	Signature string
	// This is only populated when you Parse/Verify a token
	Valid bool
}

func New(method SigningMethod) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
		},
		Claims: make(map[string]interface{}),
	}
}

// Get the complete, signed token
func (t *Token) SignedString(key []byte) (string, error) {
	sstr, err := t.SigningString()
	if err != nil {
		return "", err
	}

	sig, err := t.Method.Sign(sstr, key)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{sstr, sig}, "."), nil
}

// Generate the signing string.  This is the
// most expensive part of the whole deal.  Unless you
// need this for something special, just go straight for
// the SignedString.
func (t *Token) SigningString() (string, error) {
	first, err := jsonMarshal(t.Header)
	if err != nil {
		return "", err
	}

	second, err := jsonMarshal(t.Claims)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{first, second}, "."), nil
}

func jsonMarshal(m map[string]interface{}) (string, error) {
	jsonValue, err := json.Marshal(m)
	return EncodeSegment(jsonValue), err
}

// Parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	token := new(Token)

	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		// parse Header
		err := decUnmarshal(parts[0], &token.Header)
		if err != nil {
			return token, err
		}

		// parse Claims
		err = decUnmarshal(parts[1], &token.Claims)
		if err != nil {
			return token, err
		}

		// Lookup signature method
		method, ok := token.Header["alg"].(string)
		if !ok {
			return token, errors.New("Signing method (alg) is unspecified.")
		}

		if token.Method, err = GetSigningMethod(method); err != nil {
			return token, err
		}

		// Check expiry times
		if exp, ok := token.Claims["exp"].(int64); ok && time.Now().Unix() > exp {
			return token, errors.New("Token is expired")
		}

		// Lookup key
		key, err := keyFunc(token)
		if err != nil {
			return token, err
		}

		// Perform validation
		if err = token.Method.Verify(strings.Join(parts[:2], "."), parts[2], key); err != nil {
			return token, err
		}

		token.Valid = true
		return token, err
	}
	return token, errors.New("Token contains an invalid number of segments")
}

func decUnmarshal(data string, m *map[string]interface{}) error {
	var b []byte
	b, err := DecodeSegment(data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, m); err != nil {
		return err
	}

	return nil
}

// Try to find the token in an http.Request.
// Currently, it only looks in the Authorization header
func ParseFromRequest(req *http.Request, keyFunc Keyfunc) (token *Token, err error) {

	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			return Parse(ah[7:], keyFunc)
		}
	}

	return nil, errors.New("No token present in request.")

}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	// len % 4
	switch len(seg) % 4 {
	case 2:
		seg = seg + "=="
	case 3:
		seg = seg + "==="
	}

	return base64.URLEncoding.DecodeString(seg)
}
