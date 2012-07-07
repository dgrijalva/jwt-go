package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

var (
	ErrInvSig = errors.New("Signature is invalid")
)

type SigningMethodHS256 struct{}

func init() {
	RegisterSigningMethod("HS256", func() SigningMethod {
		return new(SigningMethodHS256)
	})
}

func (m *SigningMethodHS256) Alg() string {
	return "HS256"
}

func (m *SigningMethodHS256) Verify(signingString, signature string, key []byte) error {
	// Key
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}

	hasher := hmac.New(sha256.New, key)
	hasher.Write([]byte(signingString))

	if !bytes.Equal(sig, hasher.Sum(nil)) {
		return ErrInvSig
	}

	return nil
}

func (m *SigningMethodHS256) Sign(signingString string, key []byte) (string, error) {
	hasher := hmac.New(sha256.New, key)
	hasher.Write([]byte(signingString))

	return EncodeSegment(hasher.Sum(nil)), nil
}
