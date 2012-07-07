package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type SigningMethodRS256 struct{}

func init() {
	RegisterSigningMethod("RS256", func() SigningMethod {
		return new(SigningMethodRS256)
	})
}

func (m *SigningMethodRS256) Alg() string {
	return "RS256"
}

func (m *SigningMethodRS256) Verify(signingString, signature string, key []byte) (err error) {
	// Key
	sig, err := DecodeSegment(signature)
	if err != nil {
		return

	}

	block, _ := pem.Decode(key)
	if block == nil {
		err = errors.New("Could not parse key data")
		return
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		err = errors.New("Key is not a valid RSA public key")
		return
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hasher.Sum(nil), sig)
	return
}

func (m *SigningMethodRS256) Sign(signingString string, key []byte) (sig string, err error) {
	// Key
	rsaKey, err := m.parsePrivateKey(key)
	if err != nil {
		return
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		return
	}

	sig = EncodeSegment(sigBytes)
	return
}

func (m *SigningMethodRS256) parsePrivateKey(key []byte) (pkey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return
		}
	}

	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		err = errors.New("Key is not a valid RSA private key")
	}
	return
}
