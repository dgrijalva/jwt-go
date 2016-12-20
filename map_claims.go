package jwt

import (
	"encoding/json"
	"errors"
	//"fmt"
)

// Claims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// Compares the aud claim against cmp.
// If the aud claim is a string, this method will return true if the value matches exactly.
// If the aud claim is a slice of strings, this method will return true if the value exactly matches any of the items in the slice.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud := m["aud"]

	switch aud.(type) {
	default:
		// Unknown types are treated as if there were no "aud" claim
		return verifyAud([]string{}, cmp, req)
	case string:
		// Single item case
		return verifyAud([]string{aud.(string)}, cmp, req)
	case []string:

		return verifyAud(aud.([]string), cmp, req)
	case []interface{}:
		// The result of parsing a token into MapClaims from JSON is an []interface{}.
		strAud := []string{}
		for _, a := range aud.([]interface{}) {
			switch a.(type) {
			default:
				return verifyAud([]string{}, cmp, req)
			case string:
				strAud = append(strAud, a.(string))
			}
		}
		return verifyAud(strAud, cmp, req)

	}
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
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= ValidationErrorExpired
	}

	if m.VerifyIssuedAt(now, false) == false {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if m.VerifyNotBefore(now, false) == false {
		vErr.Inner = errors.New("Token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}
