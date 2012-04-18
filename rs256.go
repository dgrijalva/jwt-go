package jwt

import (
	"errors"
	"encoding/pem"
	"crypto"
	"crypto/x509"
	"crypto/rsa"
	"crypto/sha256"
)

type SigningMethodRS256 struct {}

func init() {
	RegisterSigningMethod("RS256", func() SigningMethod {
		return new(SigningMethodRS256)
	})
}

func (m *SigningMethodRS256) Verify(signingString, signature string, key []byte)(err error) {
	// Key
	var sig []byte
	if sig, err = DecodeSegment(signature); err == nil {
		var block *pem.Block
		if block, _ = pem.Decode(key); block != nil {
			var parsedKey interface{}
			if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				if rsaKey, ok := parsedKey.(*rsa.PublicKey); ok {
					hasher := sha256.New()
					hasher.Write([]byte(signingString))
					
					err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hasher.Sum(nil), sig)
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

func (m *SigningMethodRS256) Sign(token *Token, key []byte)error {
	return nil
}