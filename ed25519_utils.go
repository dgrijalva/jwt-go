package jwt

import (
	"encoding/asn1"
	"encoding/pem"
	"golang.org/x/crypto/ed25519"
)

type OI struct {
	ObjectIdentifier asn1.ObjectIdentifier
}

type ed25519PrivKey struct {
	Version          int
	ObjectIdentifier OI
	PrivateKey       []byte
}

type ed25519PubKey struct {
	OBjectIdentifier OI
	PublicKey        asn1.BitString
}

// https://tools.ietf.org/id/draft-ietf-curdle-pkix-06.html#rfc.section.7
func ParseED25519PrivateKeyFromPEM(key []byte) (*ed25519.PrivateKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}
	var asn1PrivKey ed25519PrivKey
	if _, err := asn1.Unmarshal(block.Bytes, &asn1PrivKey); err != nil {
		return nil, err
	}
	// we don't need the tag and length bytes
	privKey := ed25519.NewKeyFromSeed(asn1PrivKey.PrivateKey[2:])
	return &privKey, nil
}

func ParseED25519PublicKeyFromPEM(key []byte) (*ed25519.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}
	var asn1PubKey ed25519PubKey
	if _, err := asn1.Unmarshal(block.Bytes, &asn1PubKey); err != nil {
		return nil, err
	}
	pkey := ed25519.PublicKey(asn1PubKey.PublicKey.Bytes)
	return &pkey, nil
}
