package jwt_test

import (
	"errors"
	"fmt"
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

func (c *TestClaim) ExpiresAt() (int64, error) {
	return c.Expiration, nil
}

func (c *TestClaim) ValidNotBefore() (int64, error) {
	return 0, errors.New("not implemented")
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
