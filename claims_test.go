package jwt

import (
	"testing"
)

// Test StandardClaims instances with an audience value populated in a string, []string and []interface{}
var audienceValue = "Aud"
var unmatchedAudienceValue = audienceValue + "Test"
var claimWithAudience = []StandardClaims{
	{
		audienceValue,
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
	{
		[]string{audienceValue, unmatchedAudienceValue},
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
	{
		[]interface{}{audienceValue, unmatchedAudienceValue},
		123123,
		"Id",
		12312,
		"Issuer",
		12312,
		"Subject",
	},
}

// Test StandardClaims instances with no aduences within empty []string and []interface{} collections.
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

func TestExtractAudienceWithAudienceValues(t *testing.T) {
	for _, data := range claimWithAudience {
		var aud = ExtractAudience(&data)
		if len(aud) == 0 || aud[0] != audienceValue {
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
	[]string{audienceValue},
	[]string{"Aud1", "Aud2", audienceValue},
}

var audWithLackingOriginalValue = [][]string{
	[]string{},
	[]string{audienceValue + "1"},
	[]string{"Aud1", "Aud2", audienceValue + "1"},
}

func TestVerifyAud_ShouldVerifyExists(t *testing.T) {
	for _, data := range audWithValues {
		if !verifyAud(data, audienceValue, true) {
			t.Errorf("The audience value was not verified properly")
		}
	}
}

func TestVerifyAud_ShouldVerifyDoesNotExist(t *testing.T) {
	for _, data := range audWithValues {
		if !verifyAud(data, audienceValue, true) {
			t.Errorf("The audience value was not verified properly")
		}
	}
}
