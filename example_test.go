package jwt_test

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func ExampleParse(myToken string, myLookupKey func(interface{}) (interface{}, error)) {
	token, err := jwt.Parse(jwt.ParseParam{
		TokenString: myToken,
		Method: jwt.SigningMethodRS256,
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			return myLookupKey(token.Header["kid"])
		}})

	if err == nil && token.Valid {
		fmt.Println("Your token is valid.  I like your style.")
	} else {
		fmt.Println("This token is terrible!  I cannot accept this.")
	}
}

func ExampleNew() {
	// Create the token
	token := jwt.New(jwt.SigningMethodRS256)

	// Set some claims
	claims := token.Claims.(jwt.MapClaims)
	claims["foo"] = "bar"
	claims["exp"] = time.Unix(0, 0).Add(time.Hour * 1).Unix()

	fmt.Printf("<%T> foo:%v exp:%v\n", token.Claims, claims["foo"], claims["exp"])
	//Output: <jwt.MapClaims> foo:bar exp:3600
}

func ExampleNewWithClaims() {
	mySigningKey := []byte("AllYourBase")

	// Create the Claims
	claims := jwt.StandardClaims{
		ExpiresAt: 15000,
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	fmt.Printf("%v %v", ss, err)
	//Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.QsODzZu3lUZMVdhbO76u3Jv02iYCvEHcYVUI1kOWEU0 <nil>
}

func ExampleNewWithClaims_customType() {
	mySigningKey := []byte("AllYourBase")

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.StandardClaims
	}

	// Create the Claims
	claims := MyCustomClaims{
		"bar",
		jwt.StandardClaims{
			ExpiresAt: 15000,
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	fmt.Printf("%v %v", ss, err)
	//Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c <nil>
}

func ExampleParse_errorChecking(myToken string, myLookupKey func(interface{}) (interface{}, error)) {
	token, err := jwt.Parse(jwt.ParseParam{
		TokenString: myToken,
		Method: jwt.SigningMethodRS256,
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			return myLookupKey(token.Header["kid"])
		}})

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
