## Example Implementation JWT GO

### Example JWT Sign

```go
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
```

### Example JWT Verify

```go
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

	verifiedToken, errTokenVerified := util.VerifyToken(accessToken, util.GodotEnv("JWT_SECRET"))

	if errToken != nil {
		logrus.Fatal(errTokenVerified.Error())
	}

	fmt.Println("my verified accessToken here", verifiedToken)
}
```

### Example JWT Decoded

```go
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

	verifiedToken, errTokenVerified := util.VerifyToken(accessToken, util.GodotEnv("JWT_SECRET"))

	if errToken != nil {
		logrus.Fatal(errTokenVerified.Error())
	}

 decodedToken := util.DecodedToken(verifiedToken)

	fmt.Println("my decoded accessToken here", decodedToken.Claims.Email)
}
```