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

// For a type to be a Claims object, it must just have a Valid method that determines
// if the token is invalid for any supported reason
type Claimer interface {
	Valid() error
}

// Structured version of Claims Section, as referenced at https://tools.ietf.org/html/rfc7519#section-4.1
type Claims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

func (c Claims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	// The claims below are optional, so if they are set to the default value in Go, let's not
	// verify them.

	if c.ExpiresAt != 0 {
		if c.VerifyExpiresAt(now) == false {
			vErr.err = "Token is expired"
			vErr.Errors |= ValidationErrorExpired
		}
	}

	if c.IssuedAt != 0 {
		if c.VerifyIssuedAt(now) == false {
			vErr.err = "Token used before issued, clock skew issue?"
			vErr.Errors |= ValidationErrorIssuedAt
		}
	}

	if c.NotBefore != 0 {
		if c.VerifyNotBefore(now) == false {
			vErr.err = "Token is not valid yet"
			vErr.Errors |= ValidationErrorNotValidYet
		}
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

func (c *Claims) VerifyAudience(cmp string) bool {
	return verifyAud(c.Audience, cmp)
}

func (c *Claims) VerifyExpiresAt(cmp int64) bool {
	return verifyExp(c.ExpiresAt, cmp)
}

func (c *Claims) VerifyIssuedAt(cmp int64) bool {
	return verifyIat(c.IssuedAt, cmp)
}

func (c *Claims) VerifyIssuer(cmp string) bool {
	return verifyIss(c.Issuer, cmp)
}

func (c *Claims) VerifyNotBefore(cmp int64) bool {
	return verifyNbf(c.NotBefore, cmp)
}

type MapClaim map[string]interface{}

func (m MapClaim) VerifyAudience(cmp string) bool {
	val, exists := m["aud"]
	if !exists {
		return true // Don't fail validation if claim doesn't exist
	}

	if aud, ok := val.(string); ok {
		return verifyAud(aud, cmp)
	}
	return false
}

func (m MapClaim) VerifyExpiresAt(cmp int64) bool {
	val, exists := m["exp"]
	if !exists {
		return true
	}

	if exp, ok := val.(float64); ok {
		return verifyExp(int64(exp), cmp)
	}
	return false
}

func (m MapClaim) VerifyIssuedAt(cmp int64) bool {
	val, exists := m["iat"]
	if !exists {
		return true
	}

	if iat, ok := val.(float64); ok {
		return verifyIat(int64(iat), cmp)
	}
	return false
}

func (m MapClaim) VerifyIssuer(cmp string) bool {
	val, exists := m["iss"]
	if !exists {
		return true
	}

	if iss, ok := val.(string); ok {
		return verifyIss(iss, cmp)
	}
	return false
}

func (m MapClaim) VerifyNotBefore(cmp int64) bool {
	val, exists := m["nbf"]
	if !exists {
		return true
	}

	if nbf, ok := val.(float64); ok {
		return verifyNbf(int64(nbf), cmp)
	}
	return false
}

func (m MapClaim) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	if m.VerifyExpiresAt(now) == false {
		vErr.err = "Token is expired"
		vErr.Errors |= ValidationErrorExpired
	}

	if m.VerifyIssuedAt(now) == false {
		vErr.err = "Token used before issued, clock skew issue?"
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if m.VerifyNotBefore(now) == false {
		vErr.err = "Token is not valid yet"
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

func verifyAud(aud string, cmp string) bool {
	return aud == cmp
}

func verifyExp(exp int64, now int64) bool {
	return now <= exp
}

func verifyIat(iat int64, now int64) bool {
	return now >= iat
}

func verifyIss(iss string, cmp string) bool {
	return iss == cmp
}

func verifyNbf(nbf int64, now int64) bool {
	return now >= nbf
}

// A JWT Token.  Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
type Token struct {
	Raw       string                 // The raw token.  Populated when you Parse a token
	Method    SigningMethod          // The signing method used or to be used
	Header    map[string]interface{} // The first segment of the token
	Claims    Claimer                // The second segment of the token
	Signature string                 // The third segment of the token.  Populated when you Parse a token
	Valid     bool                   // Is the token valid?  Populated when you Parse/Verify a token
}

// Create a new Token.  Takes a signing method
func New(method SigningMethod) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
		},
		Claims: Claims{},
		Method: method,
	}
}

func NewWithClaims(method SigningMethod, claims Claimer) *Token {
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
func Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return ParseWithClaims(tokenString, keyFunc, &Claims{})
}

func ParseWithClaims(tokenString string, keyFunc Keyfunc, claims Claimer) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, &ValidationError{err: "token contains an invalid number of segments", Errors: ValidationErrorMalformed}
	}

	var err error
	token := &Token{
		Raw: tokenString,
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

	if err = json.Unmarshal(claimBytes, &claims); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}
	token.Claims = claims

	// Lookup signature method
	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, &ValidationError{err: "signing method (alg) is unavailable.", Errors: ValidationErrorUnverifiable}
		}
	} else {
		return token, &ValidationError{err: "signing method (alg) is unspecified.", Errors: ValidationErrorUnverifiable}
	}

	// Lookup key
	var key interface{}
	if keyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, &ValidationError{err: "no Keyfunc was provided.", Errors: ValidationErrorUnverifiable}
	}
	if key, err = keyFunc(token); err != nil {
		// keyFunc returned an error
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorUnverifiable}
	}

	var vErr *ValidationError

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

	if vErr == nil || vErr.valid() {
		token.Valid = true
		return token, nil
	}

	return token, vErr
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
