package jwt

import (
	"testing"
)

var fixedAudienceKeyForClaims = "Aud"
var claimWithAudience = []StandardClaims{
	{
		fixedAudienceKeyForClaims,
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
	{
		[]string{fixedAudienceKeyForClaims},
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
	{
		[]interface{}{fixedAudienceKeyForClaims},
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
}

var claimWithoutAudience = []StandardClaims{
	{
		[]string{},
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
	{
		[]interface{}{},
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
}

func TestExtractAudience_WithAudienceValues(t *testing.T) {
	for _, data := range claimWithAudience {
		var aud = ExtractAudience(&data)
		if len(aud) == 0 || aud[0] != fixedAudienceKeyForClaims {
			t.Errorf("The audience value was not extracted properly")
		}
	}
}

func TestExtractAudience_WithoutAudienceValues(t *testing.T) {
	for _, data := range claimWithoutAudience {
		var aud = ExtractAudience(&data)
		if len(aud) != 0 {
			t.Errorf("An audience value should not have been extracted")
		}
	}
}

var audWithValues = [][]string{
	[]string{fixedAudienceKeyForClaims},
	[]string{"Aud1", "Aud2", fixedAudienceKeyForClaims},
}

var audWithLackingOriginalValue = [][]string{
	[]string{},
	[]string{fixedAudienceKeyForClaims + "1"},
	[]string{"Aud1", "Aud2", fixedAudienceKeyForClaims + "1"},
}

func TestVerifyAud_ShouldVerifyExists(t *testing.T) {
	for _, data := range audWithValues {
		if !verifyAud(data, fixedAudienceKeyForClaims, true) {
			t.Errorf("The audience value was not verified properly")
		}
	}
}

func TestVerifyAud_ShouldVerifyDoesNotExist(t *testing.T) {
	for _, data := range audWithValues {
		if !verifyAud(data, fixedAudienceKeyForClaims, true) {
			t.Errorf("The audience value was not verified properly")
		}
	}
}
