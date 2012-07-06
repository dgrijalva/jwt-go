A [golang](http://www.golang.org) implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-jones-json-web-token.html)

This library is still a work in progress.  Feedback is appreciated.  This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are RSA256 and HMAC SHA256.

## Parse and Verify

	token, err := jwt.Parse(myToken, func(token *jwt.Token)([]byte, error){
		return myLookupKey(token.Head["kid"])
	})
	
	if !err && token.Valid {
		deliverGoodness("!")
	} else {
		deliverUtterRejection(":(")
	}
	
## Create a token
	
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["foo"] = "bar"
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	tokenString, err := token.SignedString(mySigningKey)