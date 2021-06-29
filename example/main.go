package main

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

// example usage
func main() {

	secretKey := util.GodotEnv("JWT_SECRET")
	userData := map[string]interface{}{"id": 1, "email": "johndoe13@gmail.com"}
	accessToken, errToken := util.Sign(userData, secretKey, 5) // data -> secretkey -> expireAt

	if errToken != nil {
		logrus.Fatal(errToken.Error())
	}

	fmt.Println("my accessToken here", accessToken)
}
