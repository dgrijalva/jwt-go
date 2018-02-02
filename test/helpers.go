package test

import (
	"crypto/rsa"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

func LoadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func MakeSampleToken(o []jwt.TokenOption, c jwt.Claims, key interface{}) string {
	o = append(o, jwt.WithSigningMethod(jwt.SigningMethodRS256))
	o = append(o, jwt.WithClaims(c))
	token, e := jwt.NewWithOptions(o...)
	if e != nil {
		panic(e.Error())
	}

	s, e := token.SignedString(key)
	if e != nil {
		panic(e.Error())
	}

	return s
}
