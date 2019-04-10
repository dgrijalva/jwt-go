package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// Claims is the interface used to hold the claims values of a token
// For a type to be a Claims object, it must have a Valid method that determines
// if the token is invalid for any supported reason
// opts will often be nil
// Claims are parsed and encoded using the standard library's encoding/json
// package. Claims are passed directly to that.
type Claims interface {
	Valid(opts *ValidationOptions) error
}

// Options passed in to Claims.Valid
// Currently only supports Leeway (more coming soon)
type ValidationOptions struct {
	Leeway time.Duration // allow a bit (a minute or so) of extra time to allow for clock sku
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
func (c StandardClaims) Valid(opts *ValidationOptions) error {
	vErr := new(ValidationError)
	now := Now()

	// Get leeway out of opts (if present)
	var leeway time.Duration
	if opts != nil {
		leeway = opts.Leeway
	}

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if c.VerifyExpiresAt(At(now.Add(-leeway)), false) == false {
		delta := now.Sub(c.ExpiresAt.Time)
		vErr.Inner = &ExpiredError{now.Unix(), delta, c}
		vErr.Errors |= ValidationErrorExpired
	}

	if c.VerifyNotBefore(At(now.Add(leeway)), false) == false {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// VerifyExpiresAt compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyExpiresAt(cmp *Time, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// VerifyNotBefore compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyNotBefore(cmp *Time, req bool) bool {
	return verifyNbf(c.NotBefore, cmp, req)
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

func verifyExp(exp *Time, now *Time, required bool) bool {
	if exp == nil {
		return !required
	}
	return now.Before(exp.Time)
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

func verifyNbf(nbf *Time, now *Time, required bool) bool {
	if nbf == nil {
		return !required
	}
	return nbf.Before(now.Time)
}
