package jwt

import (
	"errors"
	"golang.org/x/crypto/ed25519"
)

var (
	// Sadly this is missing from crypto/ED25519 compared to crypto/rsa
	ErrED25519Verification = errors.New("golang.org/x/ed25519: verification error")
)

// Implements the ED25519 family of signing methods signing methods
// Expects *ED25519.PrivateKey for signing and *ED25519.PublicKey for verification
type SigningMethodED25519 struct {
	Name string
}

// Specific instances for EC256 and company
var (
	ED25519 *SigningMethodED25519
)

func init() {
	ED25519 = &SigningMethodED25519{"ED25519"}
	RegisterSigningMethod(ED25519.Alg(), func() SigningMethod {
		return ED25519
	})
}

func (m *SigningMethodED25519) Alg() string {
	return m.Name
}

// Implements the Verify method from SigningMethod
// For this verify method, key must be an ED25519.PublicKey struct
func (m *SigningMethodED25519) Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	// Get the key
	var ED25519Key *ed25519.PublicKey
	var ok bool

	if ED25519Key, ok = key.(*ed25519.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	// Verify the signature
	if verifystatus := ed25519.Verify(*ED25519Key, []byte(signingString), sig); verifystatus == true {
		return nil
	} else {
		return ErrED25519Verification
	}
}

// Implements the Sign method from SigningMethod
// For this signing method, key must be an ED25519.PrivateKey struct
func (m *SigningMethodED25519) Sign(signingString string, key interface{}) (str string, err error) {
	// Get the key
	var ED25519Key *ed25519.PrivateKey
	var ok bool

	if ED25519Key, ok = key.(*ed25519.PrivateKey); !ok {
		return "", ErrInvalidKeyType
	}

	defer func(){
		if r := recover(); r != nil {
			switch x := r.(type) {
			case error:
				err = x
			case string:
				err = errors.New(x)
			}
		}
	}()
	sig := ed25519.Sign(*ED25519Key, []byte(signingString))
	return EncodeSegment(sig), nil
}
