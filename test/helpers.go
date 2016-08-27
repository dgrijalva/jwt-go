package test

import (
	"time"
	"io/ioutil"
	"crypto/rsa"

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

func MakeSampleToken(c jwt.Claims, key interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

// At overrides time value for tests.  Restore default value after.
func At(t time.Time, f func()) {
	jwt.TimeFunc = func() time.Time {
		return t
	}
	f()
	jwt.TimeFunc = time.Now
}
