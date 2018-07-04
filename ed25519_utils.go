package jwt

import (
	"encoding/pem"
	"golang.org/x/crypto/ed25519"
)


// Parse PEM encoded Elliptic Curve Private Key Structure
func ParseED25519PrivateKeyFromPEM(key []byte) (*ed25519.PrivateKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	privKey := ed25519.NewKeyFromSeed(block.Bytes[16:])
	return &privKey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseED25519PublicKeyFromPEM(key []byte) (*ed25519.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	pkey := ed25519.PublicKey(block.Bytes[12:])
	return &pkey, nil
}
