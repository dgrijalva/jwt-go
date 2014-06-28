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
	var sig []byte
	if sig, err = DecodeSegment(signature); err == nil {
		var block *pem.Block
		if block, _ = pem.Decode(key); block != nil {
			var parsedKey interface{}
			if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				parsedKey, err = x509.ParseCertificate(block.Bytes)
			}
			if err == nil {
				if rsaKey, ok := parsedKey.(*rsa.PublicKey); ok {
					hasher := sha256.New()
					hasher.Write([]byte(signingString))

					err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hasher.Sum(nil), sig)
				} else if cert, ok := parsedKey.(*x509.Certificate); ok {
					err = cert.CheckSignature(x509.SHA256WithRSA, []byte(signingString), sig)
				} else {
					err = errors.New("Key is not a valid RSA public key")
				}
			}
		} else {
			err = errors.New("Could not parse key data")
		}
	}
	return
}

// Implements the Sign method from SigningMethod
// For this signing method, must be PEM encoded PKCS1 or PKCS8 RSA private key
func (m *SigningMethodRS256) Sign(signingString string, key []byte) (sig string, err error) {
	// Key
	var rsaKey *rsa.PrivateKey
	if rsaKey, err = m.parsePrivateKey(key); err == nil {
		hasher := sha256.New()
		hasher.Write([]byte(signingString))

		var sigBytes []byte
		if sigBytes, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hasher.Sum(nil)); err == nil {
			sig = EncodeSegment(sigBytes)
		}
	}
	return
}

func (m *SigningMethodRS256) parsePrivateKey(key []byte) (pkey *rsa.PrivateKey, err error) {
	var block *pem.Block
	if block, _ = pem.Decode(key); block != nil {
		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, err
			}
		}
		var ok bool
		if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
			err = errors.New("Key is not a valid RSA private key")
		}
	} else {
		err = errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	}
	return
}
