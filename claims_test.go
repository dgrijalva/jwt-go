package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/test"
)

const (
	expireAtInt = 100
	nowInt = 200
)

var claimsTestData = []struct {
	name   string
	need   string
	claims jwt.Claims
}{
	{
		name:   "Map claims expired json.Number",
		need:   "Given the need to test validating a MapClaims past its json.Number expire-at time.",
		claims: jwt.MapClaims{"exp": json.Number(fmt.Sprintf("%v", time.Unix(expireAtInt, 0).Unix()))},
	},
	{
		name:   "Map claims expired float64",
		need:   "Given the need to test validating a MapClaims past its float64 expire-at time.",
		claims: jwt.MapClaims{"exp": float64(time.Unix(expireAtInt, 0).Unix())},
	},
	{
		name:   "StandardClaims expired",
		need:   "Given the need to test validating a StandardClaims past its expire-at time.",
		claims: jwt.StandardClaims{ExpiresAt: int64(time.Unix(expireAtInt, 0).Unix())},
	},
}

func TestClaimValidExpired(t *testing.T) {
	for _, data := range claimsTestData {
		t.Log(data.name)
		t.Logf("\t%s", data.need)
		name := data.name
		t.Logf("\t\tValidate the Claims with exp as %v at time %v",  nowInt, expireAtInt)
		test.At(time.Unix(nowInt, 0), func() {
			err := data.claims.Valid()
			t.Log("\t\t\tExpect an error who's message includes the expired by 1m40s")
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", name)
			} else {
				ve := err.(*jwt.ValidationError)
				// compare the bitfield part of the error
				if e := ve.Errors; e != jwt.ValidationErrorExpired {
					t.Errorf("[%v] Errors don't match expectation.  %v != %v", name, e, jwt.ValidationErrorExpired)
				}
				expectedErrorStr := "Token is expired by 1m40s"
				if fmt.Sprint(ve.Inner.Error()) != expectedErrorStr {
					t.Errorf("[%v] Errors inner text is not as expected. \"%v\" is not \"%v\"", name, ve.Inner, expectedErrorStr)
				}
			}
		})
	}
}
