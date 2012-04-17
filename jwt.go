package jwt

import (
	"strings"
	"errors"
	"encoding/base64"
	"encoding/json"
)

// A JWT Token
type Token struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Method    SigningMethod
	Signature string
	Valid     bool
}

func Parse(tokenString string, keyFunc func(*Token)(string, error)) (token *Token, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		token = new(Token)
		// parse Header
		var headerBytes []byte
		if headerBytes, err = base64.URLEncoding.DecodeString(parts[0]); err != nil {
			return
		}
		if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
			return
		}
		
		// parse Claims
		var claimBytes []byte
		if claimBytes, err = base64.URLEncoding.DecodeString(parts[0]); err != nil {
			return
		}
		if err = json.Unmarshal(claimBytes, &token.Claims); err != nil {
			return
		}
		
		// Lookup signature method
		if method, ok := token.Header["alg"].(string); ok {
			if token.Method, err = GetSigningMethod(method); err != nil {
				return
			}
		} else {
			err = errors.New("Signing method (alg) is unspecified.")
			return
		}

		// Check expiry times
		

		// Lookup key
		
		
		
	} else {
		err = errors.New("Token contains an invalid number of segments")
	}
	return
}
