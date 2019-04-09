package jwt

import (
	"encoding/json"
	"errors"
)

// MapClaims is the Claims type that uses the map[string]interface{} for JSON decoding
// This is the default Claims type if you don't supply one
type MapClaims map[string]interface{}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud, ok := m["aud"]
	if !ok {
		return !req
	}

	cs, err := ParseClaimStrings(aud)
	if err != nil {
		return false
	}

	return verifyAud(cs, cmp, req)
}

// VerifyExpiresAt compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpiresAt(cmp *Time, req bool) bool {
	switch exp := m["exp"].(type) {
	case float64:
		return verifyExp(NewTime(exp), cmp, req)
	case json.Number:
		v, _ := exp.Float64()
		return verifyExp(NewTime(v), cmp, req)
	}
	return req == false
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss, _ := m["iss"].(string)
	return verifyIss(iss, cmp, req)
}

// VerifyNotBefore compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp *Time, req bool) bool {
	switch nbf := m["nbf"].(type) {
	case float64:
		return verifyNbf(NewTime(nbf), cmp, req)
	case json.Number:
		v, _ := nbf.Float64()
		return verifyNbf(NewTime(v), cmp, req)
	}
	return req == false
}

// Valid validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid() error {
	vErr := new(ValidationError)
	now := Now()

	if m.VerifyExpiresAt(now, false) == false {
		var expiresAt *Time
		switch exp := m["exp"].(type) {
		case float64:
			expiresAt = NewTime(exp)
		case json.Number:
			x, _ := exp.Float64()
			expiresAt = NewTime(x)
		}
		delta := now.Sub(expiresAt.Time)
		vErr.Inner = &ExpiredError{now.Unix(), delta, m}
		vErr.Errors |= ValidationErrorExpired
	}

	if m.VerifyNotBefore(now, false) == false {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}
