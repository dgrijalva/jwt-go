package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}

var (
	SigningMethodRS256 *SigningMethodRSA
	SigningMethodRS384 *SigningMethodRSA
	SigningMethodRS512 *SigningMethodRSA
	ErrInvalidKey      = errors.New("An invalid key was passed. Expected a []byte or *rsa.PrivateKey")
)

func init() {
	// RS256
	SigningMethodRS256 = &SigningMethodRSA{"RS256", crypto.SHA256}
	RegisterSigningMethod(SigningMethodRS256.Alg(), func() SigningMethod {
		return SigningMethodRS256
	})

	// RS384
	SigningMethodRS384 = &SigningMethodRSA{"RS384", crypto.SHA384}
	RegisterSigningMethod(SigningMethodRS384.Alg(), func() SigningMethod {
		return SigningMethodRS384
	})

	// RS512
	SigningMethodRS512 = &SigningMethodRSA{"RS512", crypto.SHA512}
	RegisterSigningMethod(SigningMethodRS512.Alg(), func() SigningMethod {
		return SigningMethodRS512
	})
}

func (m *SigningMethodRSA) Alg() string {
	return m.Name
}

// Implements the Verify method from SigningMethod
// For this signing method, must be either a PEM encoded PKCS1 or PKCS8 RSA private key as
// []byte, or an rsa.PrivateKey structure.
func (m *SigningMethodRSA) Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey

	switch k := key.(type) {
	case []byte:
		if rsaKey, err = ParsePublicKeyFromPEM(k); err != nil {
			return err
		}
	case *rsa.PublicKey:
		rsaKey = k
	default:
		return ErrInvalidKey
	}

	// Create hasher
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Verify the signature
	return rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)
}

// Implements the Sign method from SigningMethod
// For this signing method, must be either a PEM encoded PKCS1 or PKCS8 RSA private key as
// []byte, or an rsa.PrivateKey structure.
func (m *SigningMethodRSA) Sign(signingString string, key interface{}) (string, error) {
	var err error
	var rsaKey *rsa.PrivateKey

	switch k := key.(type) {
	case []byte:
		if rsaKey, err = ParsePrivateKeyFromPEM(k); err != nil {
			return "", err
		}
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return "", ErrInvalidKey
	}
	// Create the hasher
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil)); err == nil {
		return EncodeSegment(sigBytes), nil
	} else {
		return "", err
	}
}
