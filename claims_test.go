package jwt

import (
	"testing"
)

var claimsAudienceTestData = []struct {
	jwtAud interface{}
	checkAud string
	required bool
	valid bool
}{
	{
		"aud_test_123",
		"aud_test_123",
		true,
		true,
	},
	{
		"aud_test_123",
		"aud_test_000",
		true,
		false,
	},
	{
		"",
		"aud_test_123",
		true,
		false,
	},
	{
		"",
		"aud_test_123",
		false,
		true,
	},
	{
		"",
		"",
		false,
		true,
	},
	{
		"",
		"",
		true,
		false,
	},
	{
		[]string{"aud1", "aud2", "aud3"},
		"aud1",
		true,
		true,
	},
	{
		[]string{"aud1", "aud2", "aud3"},
		"aud0",
		true,
		false,
	},
	{
		[]interface{}{"aud1", "aud2", "aud3"},
		"aud1",
		true,
		true,
	},
	{
		[]interface{}{"aud1", "aud2", "aud3"},
		"aud0",
		true,
		false,
	},
	{
		[]interface{}{"aud1", "aud2", "aud3"},
		"aud3",
		true,
		true,
	},
	{
		[]interface{}{"aud1", "aud2", []string{"unknown", "structure"}},
		"aud1",
		true,
		false,
	},
	{
		[]interface{}{"aud1", "aud2", []string{"unknown", "structure"}},
		"aud1",
		false,
		true,
	},
}

func TestMapClaims_VerifyAudience(t *testing.T) {
	for _, data := range claimsAudienceTestData {
		m := MapClaims{"aud": data.jwtAud}

		if m.VerifyAudience(data.checkAud, data.required) != data.valid {
			t.Errorf("[%v] Audience verification failed: expected %v", data.jwtAud, data.valid)
		}
	}

}

var stdClaimsAudienceTestData = []struct {
	claims StandardClaims
	checkAud string
	required bool
	valid bool
}{
	{
		StandardClaims{Audience:"aud_test_123"},
		"aud_test_123",
		true,
		true,
	},
	{
		StandardClaims{Audience:"aud_test_123"},
		"aud_test_000",
		true,
		false,
	},
	{
		StandardClaims{},
		"aud_test_123",
		true,
		false,
	},
	{
		StandardClaims{},
		"aud_test_123",
		false,
		true,
	},
	{
		StandardClaims{},
		"",
		true,
		false,
	},
	{
		StandardClaims{},
		"",
		false,
		true,
	},
	{
		StandardClaims{Audience:"aud1,aud2,aud3"},
		"aud1",
		true,
		false,
	},
	{
		StandardClaims{Audience:"aud1,aud2,aud3"},
		"aud0",
		true,
		false,
	},
	{
		StandardClaims{Audience:"aud1,aud2,aud3"},
		"aud1,aud2,aud3",
		true,
		true,
	},
}

func TestStandardClaims_VerifyAudience(t *testing.T) {
	for _, data := range stdClaimsAudienceTestData {
		if data.claims.VerifyAudience(data.checkAud, data.required) != data.valid {
			t.Errorf("[%v] Audience verification failed: expected %v", data.claims, data.valid)
		}
	}
}