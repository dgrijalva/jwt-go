A [go](http://www.golang.org) (or 'golang' for search engine friendliness) implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-jones-json-web-token.html)

## What the heck is a JWT?

In short, it's a signed JSON object that does something useful (for example, authentication).  It's commonly used for `Bearer` tokens in Oauth 2.  A token is made of three parts, separated by `.`'s.  The first two parts are JSON objects, that have been [base64url](http://tools.ietf.org/html/rfc4648) encoded.  The last part is the signature, encoded the same way.

The first part is called the header.  It contains the necessary information for verifying the last part, the signature.  For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit.  It's called the Claims and contains the actual stuff you care about.  Refer to [the RFC](http://self-issued.info/docs/draft-jones-json-web-token.html) for information about reserved keys and the proper way to add your own.

## What's in the box?

This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are RSA256 and HMAC SHA256, though hooks are present for adding your own.

This library is considered production ready.  Feedback and feature requests are appreciated.

## Parse and Verify

Parsing and verifying tokens is pretty straight forward.  You pass in the token and a function for looking up the key.  This is done as a callback since you may need to parse the token to find out what signing method and key was used.

```go
	token, err := jwt.Parse(myToken, func(token *jwt.Token) ([]byte, error) {
		return myLookupKey(token.Header["kid"])
	})

	if err == nil && token.Valid {
		deliverGoodness("!")
	} else {
		deliverUtterRejection(":(")
	}
```
	
## Create a token

```go
	// Create the token
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	// Set some claims
	token.Claims["foo"] = "bar"
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(mySigningKey)
```	

Documentation can be found [here](http://godoc.org/github.com/dgrijalva/jwt-go)
