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

func (m *SigningMethodRS256) Verify(signingString, signature string, key []byte) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	// Parse public key
	var rsaKey *rsa.PublicKey
	if rsaKey, err = m.parsePublicKey(key); err != nil {
		return err
	}

	// Create hasher
	hasher := sha256.New()
	hasher.Write([]byte(signingString))

	// Verify the signature
	return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hasher.Sum(nil), sig)
}

// Implements the Sign method from SigningMethod
// For this signing method, must be PEM encoded PKCS1 or PKCS8 RSA private key
func (m *SigningMethodRS256) Sign(signingString string, key []byte) (string, error) {
	var err error

	// Key
	var rsaKey *rsa.PrivateKey
	if rsaKey, err = m.parsePrivateKey(key); err != nil {
		return "", err
	}

	// Create the hasher
	hasher := sha256.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hasher.Sum(nil)); err == nil {
		return EncodeSegment(sigBytes), nil
	} else {
		return "", err
	}

}

// Parse PEM encoded PKCS1 or PKCS8 public key
func (m *SigningMethodRS256) parsePublicKey(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("Key is not a valid RSA public key")
	}

	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 private key
func (m *SigningMethodRS256) parsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("Key is not a valid RSA private key")
	}

	return pkey, nil
}
