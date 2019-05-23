package jwt

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

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss, _ := m["iss"].(string)
	return verifyIss(iss, cmp, req)
}

// Valid validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid(h *ValidationHelper) error {
	var vErr error

	if h == nil {
		h = DefaultValidationHelper
	}

	exp, err := m.LoadTimeValue("exp")
	if err != nil {
		return err
	}

	if err = h.ValidateExpiresAt(exp); err != nil {
		vErr = wrap(err, vErr)
	}

	nbf, err := m.LoadTimeValue("nbf")
	if err != nil {
		return err
	}

	if err = h.ValidateNotBefore(nbf); err != nil {
		vErr = wrap(err, vErr)
	}

	return vErr
}

// LoadTimeValue extracts a *Time value from a key in m
func (m MapClaims) LoadTimeValue(key string) (*Time, error) {
	value, ok := m[key]
	if !ok {
		// No value present in map
		return nil, nil
	}

	return ParseTime(value)
}
