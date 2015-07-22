package jwt_test

import (
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

func ExampleNew() {
	// Create the token
	token := jwt.New(jwt.SigningMethodRS256)

	// Set some claims
	claims := token.Claims.(jwt.MapClaim)
	claims["foo"] = "bar"
	claims["exp"] = time.Unix(0, 0).Add(time.Hour * 1).Unix()

	fmt.Printf("%v\n", claims)
	//Output: map[foo:bar exp:3600]
}

func ExampleNewWithClaims(mySigningKey []byte) (string, error) {
	// Create the Claims
	claims := jwt.StandardClaims{
		ExpiresAt: 15000,
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(mySigningKey)
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
