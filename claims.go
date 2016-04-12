package jwt

import (
	"crypto/subtle"
	"encoding/json"
)

// For a type to be a Claims object, it must just have a Valid method that determines
// if the token is invalid for any supported reason
type Claims interface {
	Valid() error
}

// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
type StandardClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c StandardClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if c.VerifyExpiresAt(now, false) == false {
		vErr.err = "Token is expired"
		vErr.Errors |= ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now, false) == false {
		vErr.err = "Token used before issued, clock skew issue?"
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now, false) == false {
		vErr.err = "Token is not valid yet"
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	return verifyIat(c.IssuedAt, cmp, req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyNotBefore(cmp int64, req bool) bool {
	return verifyNbf(c.NotBefore, cmp, req)
}

type MapClaims map[string]interface{}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud, _ := m["aud"].(string)
	return verifyAud(aud, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	switch exp := m["exp"].(type) {
	case float64:
		return verifyExp(int64(exp), cmp, req)
	case json.Number:
		v, _ := exp.Int64()
		return verifyExp(v, cmp, req)
	}
	return req == false
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	switch iat := m["iat"].(type) {
	case float64:
		return verifyIat(int64(iat), cmp, req)
	case json.Number:
		v, _ := iat.Int64()
		return verifyIat(v, cmp, req)
	}
	return req == false
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss, _ := m["iss"].(string)
	return verifyIss(iss, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	switch nbf := m["nbf"].(type) {
	case float64:
		return verifyNbf(int64(nbf), cmp, req)
	case json.Number:
		v, _ := nbf.Int64()
		return verifyNbf(v, cmp, req)
	}
	return req == false
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	if m.VerifyExpiresAt(now, false) == false {
		vErr.err = "Token is expired"
		vErr.Errors |= ValidationErrorExpired
	}

	if m.VerifyIssuedAt(now, false) == false {
		vErr.err = "Token used before issued, clock skew issue?"
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if m.VerifyNotBefore(now, false) == false {
		vErr.err = "Token is not valid yet"
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

func verifyAud(aud string, cmp string, required bool) bool {
	if aud == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyNbf(nbf int64, now int64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}
