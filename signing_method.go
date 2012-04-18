package jwt

import (
	"errors"
	"fmt"
)

var signingMethods = map[string]func() SigningMethod{}

// Signing method
type SigningMethod interface {
	Verify(signingString, signature string, key []byte) error
	Sign(token *Token, key []byte) error
}

func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethods[alg] = f
}

func GetSigningMethod(alg string) (method SigningMethod, err error) {
	if methodF, ok := signingMethods[alg]; ok {
		method = methodF()
	} else {
		err = errors.New(fmt.Sprintf("Invalid signing method (alg): %v", method))
	}
	return
}
