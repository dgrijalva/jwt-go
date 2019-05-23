package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/dgrijalva/jwt-go/v4/test"
	"golang.org/x/xerrors"
)

const (
	expireAt = 100
	nowInt   = 200
)

var claimsTestData = []struct {
	name   string
	need   string
	claims jwt.Claims
}{
	{
		name:   "Map claims expired json.Number",
		need:   "Given the need to test validating a MapClaims past its json.Number expire-at time.",
		claims: jwt.MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Unix(expireAt, 0).Unix()))},
	},
	{
		name:   "Map claims expired float64",
		need:   "Given the need to test validating a MapClaims past its float64 expire-at time.",
		claims: jwt.MapClaims{"foo": "bar", "exp": float64(time.Unix(expireAt, 0).Unix())},
	},
	{
		name:   "StandardClaims expired",
		need:   "Given the need to test validating a StandardClaims past its expire-at time.",
		claims: jwt.StandardClaims{ExpiresAt: jwt.NewTime(expireAt)},
	},
}

func TestClaimValidExpired(t *testing.T) {
	for _, data := range claimsTestData {
		t.Log(data.name)
		t.Logf("\t%s", data.need)
		name := data.name
		t.Logf("\t\tValidate the Claims with exp as %v at time %v", nowInt, expireAt)
		test.At(time.Unix(nowInt, 0), func() {
			err := data.claims.Valid(nil)
			t.Log("\t\t\tExpect an error that includes the expired by 1m40s information")
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", name)
			} else {
				var expErr *jwt.TokenExpiredError

				if !xerrors.As(err, &expErr) {
					t.Errorf("[%v] Expected error to unwrap as *jwt.TokenExpiredError but it didn't", name)
					return
				}

				expectedErrorStr := "token is expired by 1m40s"
				if expErr.Error() != expectedErrorStr {
					t.Errorf("[%v] Error message is not as expected \"%v\" != \"%v\"", name, expErr.Error(), expectedErrorStr)
				}
			}
		})
	}
}
