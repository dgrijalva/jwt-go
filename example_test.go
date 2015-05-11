package jwt_test

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func ExampleParse(myToken string, myLookupKey func(interface{}) (interface{}, error)) {
	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		return myLookupKey(token.Header["kid"])
	})

	if err == nil && token.Valid {
		fmt.Println("Your token is valid.  I like your style.")
	} else {
		fmt.Println("This token is terrible!  I cannot accept this.")
	}
}

func ExampleNew(mySigningKey []byte) (string, error) {
	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	token.Claims.(jwt.MapClaim)["foo"] = "bar"
	token.Claims.(jwt.MapClaim)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(mySigningKey)
	return tokenString, err
}

type TestClaim struct {
	Foo        string `json:"foo"`
	Expiration int64  `json:"exp"`
}

func (c *TestClaim) ExpiresAt() (int64, bool) {
	return c.Expiration, true
}

func (c *TestClaim) ValidNotBefore() (int64, bool) {
	return 0, false
}

func ExampleNewInterface(mySigningKey []byte) (string, error) {
	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	token.Claims = &TestClaim{
		Foo:        "bar",
		Expiration: time.Now().Add(time.Hour * 72).Unix(),
	}
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(mySigningKey)
	return tokenString, err
}

func TestNewInterface(t *testing.T) {
	key := []byte("test")
	goal := &TestClaim{
		Foo:        "bar",
		Expiration: time.Now().Add(time.Hour * 72).Unix(),
	}

	myToken := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	myToken.Claims = goal
	// Sign and get the complete encoded token as a string
	tokenString, err := myToken.SignedString(key)
	if err != nil {
		t.Error(err)
	}

	token, err := jwt.ParseInterface(tokenString, func(token *jwt.Token) (interface{}, error) {
		return "yes", nil
	}, &TestClaim{})

	if !reflect.DeepEqual(goal, token.Claims) {
		t.Errorf("expected %s to be %s\n", goal, token.Claims)
	}
}

func ExampleParse_errorChecking(myToken string, myLookupKey func(interface{}) (interface{}, error)) {
	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		return myLookupKey(token.Header["kid"])
	})

	if token.Valid {
		fmt.Println("You look nice today")
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			fmt.Println("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			fmt.Println("Timing is everything")
		} else {
			fmt.Println("Couldn't handle this token:", err)
		}
	} else {
		fmt.Println("Couldn't handle this token:", err)
	}

}
