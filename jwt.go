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
	Raw    string
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
		Method: method,
	}
}

// Get the complete, signed token
func (t *Token) SignedString(key []byte) (string, error) {
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
		var source map[string]interface{}
		if i == 0 {
			source = t.Header
		} else {
			source = t.Claims
		}

		var jsonValue []byte
		if jsonValue, err = json.Marshal(source); err != nil {
			return "", err
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil
}

// Parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func Parse(tokenString string, keyFunc Keyfunc) (token *Token, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		token = &Token{Raw: tokenString}
		// parse Header
		var headerBytes []byte
		if headerBytes, err = DecodeSegment(parts[0]); err != nil {
			return
		}
		if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
			return
		}

		// parse Claims
		var claimBytes []byte
		if claimBytes, err = DecodeSegment(parts[1]); err != nil {
			return
		}
		if err = json.Unmarshal(claimBytes, &token.Claims); err != nil {
			return
		}

		// Lookup signature method
		if method, ok := token.Header["alg"].(string); ok {
			if token.Method = GetSigningMethod(method); token.Method == nil {
				err = errors.New("Signing method (alg) is unavailable.")
				return
			}
		} else {
			err = errors.New("Signing method (alg) is unspecified.")
			return
		}

		// Check expiry times
		if exp, ok := token.Claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				err = errors.New("Token is expired")
			}
		}

		// Lookup key
		var key []byte
		if key, err = keyFunc(token); err != nil {
			return
		}

		// Perform validation
		if err = token.Method.Verify(strings.Join(parts[0:2], "."), parts[2], key); err == nil {
			token.Valid = true
		}

	} else {
		err = errors.New("Token contains an invalid number of segments")
	}
	return
}

// Try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.
func ParseFromRequest(req *http.Request, keyFunc Keyfunc) (token *Token, err error) {

	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			return Parse(ah[7:], keyFunc)
		}
	}

	// Look for "access_token" parameter
	req.ParseMultipartForm(10e6)
	if tokStr := req.Form.Get("access_token"); tokStr != "" {
		return Parse(tokStr, keyFunc)
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
