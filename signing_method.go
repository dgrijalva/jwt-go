package jwt

import (
	"errors"
	"fmt"
)

var signingMethods = map[string]func() SigningMethod{}

// Signing method
type SigningMethod interface {
	Verify(signingString, signature string, key []byte) error
	Sign(signingString string, key []byte) (string, error)
	Alg() string
}

// Register the "alg" name and a factory function for signing method.
// This is typically done during init() in the method's implementation
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethods[alg] = f
}

// Get a signing method from an "alg" string
func GetSigningMethod(alg string) (SigningMethod, error) {
	method, ok := signingMethods[alg]
	if !ok {
		return method(), errors.New(fmt.Sprintf("Invalid signing method (alg): %v", method))
	}

	return method(), nil
}
