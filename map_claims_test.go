package jwt_test

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestMapClaims_Valid(t *testing.T) {
	now := time.Now()
	oneMinuteFromNow := json.Number(fmt.Sprint(now.Add(time.Minute).Unix()))
	oneMinuteAgo := json.Number(fmt.Sprint(now.Add(-time.Minute).Unix()))
	twoMinutesAgo := json.Number(fmt.Sprint(now.Add(-2 * time.Minute).Unix()))
	thirtySecondFromNow := json.Number(fmt.Sprint(now.Add(30*time.Second).Unix()))
	nowStr := json.Number(fmt.Sprint(now.Unix()))
	validClaims := jwt.MapClaims{
		"exp": oneMinuteFromNow,
		"iat": nowStr,
		"nbf": nowStr,
	}
	assert.NoError(t, validClaims.Valid())
	expiredClaims := jwt.MapClaims{
		"exp": oneMinuteAgo,
		"iat": twoMinutesAgo,
		"nbf": twoMinutesAgo,
	}
	assert.Error(t, expiredClaims.Valid())
	notYetValidClaims := jwt.MapClaims{
		"exp": oneMinuteFromNow,
		"iat": nowStr,
		"nbf": thirtySecondFromNow,
	}
	assert.Error(t, notYetValidClaims.Valid())
	notYetIssuedClaims := jwt.MapClaims{
		"exp": oneMinuteFromNow,
		"iat": thirtySecondFromNow,
		"nbf": thirtySecondFromNow,
	}
	assert.Error(t, notYetIssuedClaims.Valid())
}

func TestMapClaims_Valid_Float(t *testing.T) {
	now := time.Now()
	oneMinuteFromNow := float64(now.Add(time.Minute).Unix())
	oneMinuteAgo := float64(now.Add(-time.Minute).Unix())
	twoMinutesAgo := float64(now.Add(-2 * time.Minute).Unix())
	thirtySecondFromNow := float64(now.Add(30*time.Second).Unix())
	nowStr := float64(now.Unix())
	validClaims := jwt.MapClaims{
		"exp": oneMinuteFromNow,
		"iat": nowStr,
		"nbf": nowStr,
	}
	assert.NoError(t, validClaims.Valid())
	expiredClaims := jwt.MapClaims{
		"exp": oneMinuteAgo,
		"iat": twoMinutesAgo,
		"nbf": twoMinutesAgo,
	}
	assert.Error(t, expiredClaims.Valid())
	notYetValidClaims := jwt.MapClaims{
		"exp": oneMinuteFromNow,
		"iat": nowStr,
		"nbf": thirtySecondFromNow,
	}
	assert.Error(t, notYetValidClaims.Valid())
	notYetIssuedClaims := jwt.MapClaims{
		"exp": oneMinuteFromNow,
		"iat": thirtySecondFromNow,
		"nbf": thirtySecondFromNow,
	}
	assert.Error(t, notYetIssuedClaims.Valid())
}

func TestMapClaims_VerifyAudience(t *testing.T) {
	joe := "joe"
	jill := "jill"
	jack := "jack"

	claims := jwt.MapClaims{}
	assert.True(t, claims.VerifyAudience(joe, false))
	assert.False(t, claims.VerifyAudience(joe, true))

	claims = jwt.MapClaims{"aud":[]string{}}
	assert.True(t, claims.VerifyAudience(joe, false))
	assert.False(t, claims.VerifyAudience(joe, true))

	claims = jwt.MapClaims{
		"aud": joe,
	}
	assert.True(t, claims.VerifyAudience(joe, false))
	assert.False(t, claims.VerifyAudience(jill, false))
	assert.True(t, claims.VerifyAudience(joe, true))
	assert.False(t, claims.VerifyAudience(jill, true))

	claims = jwt.MapClaims{
		"aud": []string {joe, jill},
	}
	assert.True(t, claims.VerifyAudience(joe, false))
	assert.True(t, claims.VerifyAudience(joe, true))
	assert.False(t, claims.VerifyAudience(jack, false))
	assert.False(t, claims.VerifyAudience(jack, true))
}

func TestMapClaims_VerifyIssuer(t *testing.T) {
	claims := jwt.MapClaims{}
	assert.True(t, claims.VerifyIssuer("service1", false))
	assert.False(t, claims.VerifyIssuer("service1", true))

	claims = jwt.MapClaims{"iss": "service1"}
	assert.True(t, claims.VerifyIssuer("service1", false))
	assert.True(t, claims.VerifyIssuer("service1", true))

	claims = jwt.MapClaims{"iss": "service2"}
	assert.False(t, claims.VerifyIssuer("service1", false))
	assert.False(t, claims.VerifyIssuer("service1", true))
}