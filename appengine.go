// +build appengine

package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"appengine"
)

// Implements the built-in AppEngine signing method
// This method uses a private key unique to your AppEngine
// application and the key may rotate from time to time.
// https://cloud.google.com/appengine/docs/go/reference#SignBytes
// https://cloud.google.com/appengine/docs/go/appidentity/#Go_Asserting_identity_to_other_systems
type SigningMethodAppEngine struct{}

type certificates []appengine.Certificate

func init() {
	RegisterSigningMethod("AppEngine", func() SigningMethod {
		return &SigningMethodAppEngine{}
	})
}

func (s *SigningMethodAppEngine) Alg() string {
	return "AppEngine"
}

// Implements the Sign method from SigningMethod
// For this signing method, a valid appengine.Context must be
// passed as the key.
func (s *SigningMethodAppEngine) Sign(signingString string, key interface{}) (string, error) {
	var ctx appengine.Context

	switch k := key.(type) {
	case appengine.Context:
		ctx = k
	default:
		return "", ErrInvalidKey
	}

	_, signature, err := appengine.SignBytes(ctx, []byte(signingString))

	if err != nil {
		return "", err
	}

	return EncodeSegment(signature), nil
}

// Implements the Verify method from SigningMethod
// For this signing method, a valid appengine.Context must be
// passed as the key.
func (s *SigningMethodAppEngine) Verify(signingString, signature string, key interface{}) error {
	var ctx appengine.Context

	switch k := key.(type) {
	case appengine.Context:
		ctx = k
	default:
		return ErrInvalidKey
	}

	var sig []byte
	var err error
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	var certs certificates
	certs, err = appengine.PublicCertificates(ctx)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))

	var certErr error
	for _, cert := range certs {
		rsaKey, err := ParseRSAPublicKeyFromPEM(cert.Data)
		if err != nil {
			return err
		}

		if certErr = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hasher.Sum(nil), sig); certErr == nil {
			return nil
		}
	}

	return certErr
}
