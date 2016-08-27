package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/test"
)

func TestExpiredErrorStringNumber(t *testing.T) {
	t.Log("Given the need to test validating a MapClaims that is past its json.Number expire-at time.")
	name := "Map claims expired delta with a json.Number"
	t.Log("\tCreate a MapClaims with exp as a json.Number 100s in the past")
	claimExpire := json.Number(fmt.Sprintf("%v", time.Unix(100, 0).Unix()))
	claims := jwt.MapClaims{"foo": "bar", "exp": claimExpire}
	t.Logf("\tValidate the MapClaims %v", claimExpire)
	test.At(time.Unix(200, 0), func() {
		err := claims.Valid()
		t.Log("\t\tExpect an error who's message includes the expired by time of about 1m40s")
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
				t.Errorf("[%v] Errors inner text is not as expected.  %v is not %v", name, ve.Inner, expectedErrorStr)
			}
		}
	})

}

func TestExpiredErrorStringFloat(t *testing.T) {
	t.Log("Given the need to test validating a MapClaims that is past its float64 expire-at time.")
	name := "Map claims expired delta with a float64"
	t.Log("\tCreate a MapClaims with exp as a float64 100s in the past")
	claimExpire, _ := json.Number(fmt.Sprintf("%v", time.Unix(100, 0).Unix())).Float64()
	claims := jwt.MapClaims{"foo": "bar", "exp": claimExpire}
	t.Log("\tValidate the MapClaims")
	test.At(time.Unix(200, 0), func() {
		err := claims.Valid()
		t.Log("\t\tExpect an error who's message includes the expired by time of about 1m40s")
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
				t.Errorf("[%v] Errors inner text is not as expected.  %v is not %v", name, ve.Inner, expectedErrorStr)
			}
		}
	})
}
