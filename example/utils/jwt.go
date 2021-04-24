package util

import (
	"encoding/json"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

// metadata for your application, change this for your app
type MetaToken struct {
	ID            int
	Email         string
	ExpiredAt     time.Time
	Authorization bool
}

type AccessToken struct {
	Claims MetaToken
}

// created accessToken like jwt.sign in javascript
func SignToken(Data map[string]interface{}, SecrePublicKeyEnvName string, ExpiredAt time.Duration) (string, error) {

	expiredAt := time.Now().Add(time.Duration(time.Second) * ExpiredAt).Unix()

	jwtSecretKey := GodotEnv(SecrePublicKeyEnvName)

	claims := jwt.MapClaims{}
	claims["expiredAt"] = expiredAt
	claims["authorization"] = true

	for i, v := range Data {
		claims[i] = v
	}

	to := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := to.SignedString([]byte(jwtSecretKey))

	if err != nil {
		logrus.Error(err.Error())
		return accessToken, err
	}

	return accessToken, nil
}

// verified accessToken like jwt.verify in javascript
func VerifyToken(accessToken, SecrePublicKeyEnvName string) (*jwt.Token, error) {
	
	jwtSecretKey := GodotEnv(SecrePublicKeyEnvName)

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecretKey), nil
	})

	if err != nil {
		logrus.Error(err.Error())
		return nil, err
	}

	return token, nil
}

// decode accessToken like jwt.decode in javascript
func DecodeToken(accessToken *jwt.Token) AccessToken {
	var token AccessToken
	stringify, _ := json.Marshal(&accessToken)
	json.Unmarshal([]byte(stringify), &token)

	return token
}
