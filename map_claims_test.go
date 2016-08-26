package jwt_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestExpiredErrorStringNumber(t *testing.T) {
	t.Log("Given the need to test validating a MapClaims that is past its json.Number expire-at time.")
	name := "Map claims expired delta with a json.Number"
	t.Log("\tCreate a MapClaims with exp as a json.Number 100s in the past")
	claimExpire := json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))
	claims := jwt.MapClaims{"foo": "bar", "exp": claimExpire}
	t.Log("\tValidate the MapClaims")
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
		expectedErrorStr := "Token is expired by 1m4"
		if !strings.Contains(fmt.Sprint(ve.Inner.Error()), "Token is expired by 1m4") {
			t.Errorf("[%v] Errors inner text is not as expected.  %v does not contain %v", name, ve.Inner, expectedErrorStr)
		}
	}
}

func TestExpiredErrorStringFloat(t *testing.T) {
	t.Log("Given the need to test validating a MapClaims that is past its float64 expire-at time.")
	name := "Map claims expired delta with a float64"
	t.Log("\tCreate a MapClaims with exp as a float64 100s in the past")
	claimExpire, _ := json.Number(fmt.Sprintf("%v", time.Now().Unix()-100)).Float64()
	claims := jwt.MapClaims{"foo": "bar", "exp": claimExpire}
	t.Log("\tValidate the MapClaims")
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
		expectedErrorStr := "Token is expired by 1m4"
		if !strings.Contains(fmt.Sprint(ve.Inner.Error()), "Token is expired by 1m4") {
			t.Errorf("[%v] Errors inner text is not as expected.  %v does not contain %v", name, ve.Inner, expectedErrorStr)
		}
	}
}
