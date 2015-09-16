package jwt

import (
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
)

type MySigningMethod struct{}

func (m *MySigningMethod) Verify(signingString, signature string, key interface{}) error {
	return nil
}
func (m *MySigningMethod) Sign(signingString string, key interface{}) (string, error) {
	return "", nil
}
func (m *MySigningMethod) Alg() string { return "MySigningMethod's Cool Algorithm" }

func TestRegisterSigningMethod(t *testing.T) {

	jwt.RegisterSigningMethod("SuperSignerAlgorithm1000", func() jwt.SigningMethod {
		return &MySigningMethod{}
	})

	if jwt.GetSigningMethod("SuperSignerAlgorithm1000") == nil {
		t.Error("Expected SuperSignerAlgorithm1000, got nil")
	}

	jwt.RemoveSigningMethod("SuperSignerAlgorithm1000")
}

func TestRemoveSigningMethod(t *testing.T) {
	jwt.RegisterSigningMethod("SuperSignerAlgorithm1000", func() jwt.SigningMethod {
		return &MySigningMethod{}
	})

	if jwt.GetSigningMethod("SuperSignerAlgorithm1000") == nil {
		t.Error("Expected SuperSignerAlgorithm1000, got nil")
	}

	jwt.RemoveSigningMethod("SuperSignerAlgorithm1000")

	if a := jwt.GetSigningMethod("SuperSignerAlgorithm1000"); a != nil {
		t.Errorf("Expected nil, got %v", a)
	}
}
