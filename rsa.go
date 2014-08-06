package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func (m *SigningMethodRSA) Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	if keyBytes, ok := key.([]byte); ok {
		var rsaKey *rsa.PublicKey
		if rsaKey, err = m.parsePublicKey(keyBytes); err != nil {
			return err
		}

		// Create hasher
		hasher := m.Hash.New()
		hasher.Write([]byte(signingString))

		// Verify the signature
		return rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)
	} else {
		return ErrInvalidKey
	}
}

// Implements the Sign method from SigningMethod
// For this signing method, must be either a PEM encoded PKCS1 or PKCS8 RSA private key as
// []byte, or an rsa.PrivateKey structure.
func (m *SigningMethodRSA) Sign(signingString string, key interface{}) (string, error) {
	var err error
	var rsaKey *rsa.PrivateKey

	switch k := key.(type) {
	case []byte:
		if rsaKey, err = m.parsePrivateKey(k); err != nil {
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

// Parse PEM encoded PKCS1 or PKCS8 public key
func (m *SigningMethodRSA) parsePublicKey(key []byte) (*rsa.PublicKey, error) {
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
func (m *SigningMethodRSA) parsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
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
