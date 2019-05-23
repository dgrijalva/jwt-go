package jwt

import (
	"crypto/subtle"
)

// Claims is the interface used to hold the claims values of a token
// For a type to be a Claims object, it must have a Valid method that determines
// if the token is invalid for any supported reason
// Claims are parsed and encoded using the standard library's encoding/json
// package. Claims are passed directly to that.
type Claims interface {
	// A nil validation helper should use the default helper
	Valid(*ValidationHelper) error
}

// StandardClaims is a structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types
type StandardClaims struct {
	Audience  ClaimStrings `json:"aud,omitempty"`
	ExpiresAt *Time        `json:"exp,omitempty"`
	ID        string       `json:"jti,omitempty"`
	IssuedAt  *Time        `json:"iat,omitempty"`
	Issuer    string       `json:"iss,omitempty"`
	NotBefore *Time        `json:"nbf,omitempty"`
	Subject   string       `json:"sub,omitempty"`
}

// Valid implements Valid from Claims
// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c StandardClaims) Valid(h *ValidationHelper) error {
	var vErr error

	if h == nil {
		h = DefaultValidationHelper
	}

	if err := h.ValidateExpiresAt(c.ExpiresAt); err != nil {
		vErr = wrap(err, vErr)
	}

	if err := h.ValidateNotBefore(c.NotBefore); err != nil {
		vErr = wrap(err, vErr)
	}

	return vErr
}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// ----- helpers

func verifyAud(aud ClaimStrings, cmp string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}
	for _, audStr := range aud {
		if subtle.ConstantTimeCompare([]byte(audStr), []byte(cmp)) != 0 {
			return true
		}
	}
	return false
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	}
	return false

}
