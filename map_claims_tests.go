package jwt

import (
	"testing"
)

var audFixedValue = "Aud"
var audClaimsMapsWithValues = []MapClaims{
	{
		"aud": audFixedValue,
	},
	{
		"aud": []string{audFixedValue},
	},
	{
		"aud": []interface{}{audFixedValue},
	},
}

var audClaimsMapsWithoutValues = []MapClaims{
	{},
	{
		"aud": []string{},
	},
	{
		"aud": []interface{}{},
	},
}

// Verifies that for every form of the "aud" field, the audFixedValue is always verifiable
func TestVerifyAudienceWithVerifiableValues(t *testing.T) {
	for _, data := range audClaimsMapsWithValues {
		if !data.VerifyAudience(audFixedValue, true) {
			t.Errorf("The audience value was not extracted properly")
		}
	}
}

// Verifies that for every empty form of the "aud" field, the audFixedValue cannot be verified
func TestVerifyAudienceWithoutVerifiableValues(t *testing.T) {
	for _, data := range audClaimsMapsWithoutValues {
		if data.VerifyAudience(audFixedValue, true) {
			t.Errorf("The audience should not verify")
		}
	}
}
