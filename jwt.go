package jwt

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// TimeFunc provides the current time when parsing token to validate "exp" claim (expiration time).
// You can override it to use another time value.  This is useful for testing or if your
// server uses a different time zone than your tokens.
var TimeFunc = time.Now

// Parse methods use this callback function to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use propries in the
// Header of the token (such as `kid`) to identify which key to use.
type Keyfunc func(*Token) (interface{}, error)

// Variable Number of Parameters
// Introducing variable number of parameters to accommodate fixes for vulnerability
// Using this feature to fix a vulnerability raised by Tim McClean in his article dated 31 March 2015
// https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
type ParseParam struct {
	TokenString string
	KeyFunc Keyfunc
	Method SigningMethod
	Req *http.Request
	Claims Claims
}

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

// Create a new Token.  Takes a signing method
func New(method SigningMethod) *Token {
	return NewWithClaims(method, MapClaims{})
}

func NewWithClaims(method SigningMethod, claims Claims) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
		},
		Claims: claims,
		Method: method,
	}
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
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil
}

// Parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil

func Parse(parseParam ParseParam) (*Token, error) {
	if parseParam.Method == nil {
		return nil, &ValidationError{err: "Must pass verification method (alg).", Errors: ValidationErrorUnverifiable}
	}
	parts := strings.Split(parseParam.TokenString, ".")
	if len(parts) != 3 {
		return nil, &ValidationError{err: "token contains an invalid number of segments", Errors: ValidationErrorMalformed}
	}

	var err error
	token := &Token{
		Raw: parseParam.TokenString,
	}

	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}

	// parse Claims
	var claimBytes []byte

	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}

	if err = json.Unmarshal(claimBytes, &parseParam.Claims); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}

	token.Claims = parseParam.Claims

	// Lookup signature method
	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, &ValidationError{err: "signing method (alg) is unavailable.", Errors: ValidationErrorUnverifiable}
		} else if token.Method.Alg() != parseParam.Method.Alg() {
			return token, &ValidationError{err: "Header contains invalid method (alg).", Errors: ValidationErrorUnverifiable}
		}
	} else {
		return token, &ValidationError{err: "signing method (alg) is unspecified.", Errors: ValidationErrorUnverifiable}
	}

	// Lookup key
	var key interface{}
	if parseParam.KeyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, &ValidationError{err: "no Keyfunc was provided.", Errors: ValidationErrorUnverifiable}
	}
	if key, err = parseParam.KeyFunc(token); err != nil {
		// keyFunc returned an error
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorUnverifiable}
	}

	vErr := &ValidationError{}

	// Validate Claims
	if err := token.Claims.Valid(); err != nil {

		// If the Claims Valid returned an error, check if it is a validation error,
		// If it was another error type, create a ValidationError with a generic ClaimsInvalid flag set
		if e, ok := err.(*ValidationError); !ok {
			vErr = &ValidationError{err: err.Error(), Errors: ValidationErrorClaimsInvalid}
		} else {
			vErr = e
		}
	}

	// Perform validation
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), parts[2], key); err != nil {
		vErr.err = err.Error()
		vErr.Errors |= ValidationErrorSignatureInvalid
	}

	if vErr.valid() {
		token.Valid = true
		return token, nil
	}

	return token, vErr
}

// Try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.

func ParseFromRequest(parseParam ParseParam) (token *Token, err error) {
	// Look for an Authorization header
	if ah := parseParam.Req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			return Parse(ParseParam{TokenString: ah[7:], Method: parseParam.Method, KeyFunc: parseParam.KeyFunc, Claims: parseParam.Claims})
		}
	}

	// Look for "access_token" parameter
	parseParam.Req.ParseMultipartForm(10e6)
	if tokStr := parseParam.Req.Form.Get("access_token"); tokStr != "" {
		return Parse(ParseParam{TokenString: tokStr, Method: parseParam.Method, KeyFunc: parseParam.KeyFunc, Claims: parseParam.Claims})
	}

	return nil, ErrNoTokenInRequest
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
