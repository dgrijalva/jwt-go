A [go](http://www.golang.org) (or 'golang' for search engine friendliness) implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-jones-json-web-token.html)

## 2.0.0 is coming!

There are a couple open pull requests that contain breaking changes I believe are essential for moving this project forward.  We will try to make upgrading as painless as possible (and the 1.x.x versions will remain available).  If you believe this will effect you, please review the open pull requests and comment as soon as possible.  I'm planning to land these changes **Friday, Aug 22, 2014**.

The changes are very small modifications to the API, but in keeping with the spirit of semantic versioning, I'm taking any breaking change seriously.

## What the heck is a JWT?

In short, it's a signed JSON object that does something useful (for example, authentication).  It's commonly used for `Bearer` tokens in Oauth 2.  A token is made of three parts, separated by `.`'s.  The first two parts are JSON objects, that have been [base64url](http://tools.ietf.org/html/rfc4648) encoded.  The last part is the signature, encoded the same way.

The first part is called the header.  It contains the necessary information for verifying the last part, the signature.  For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit.  It's called the Claims and contains the actual stuff you care about.  Refer to [the RFC](http://self-issued.info/docs/draft-jones-json-web-token.html) for information about reserved keys and the proper way to add your own.

## What's in the box?

This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are RSA256 and HMAC SHA256, though hooks are present for adding your own.

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

## Project Status & Versioning

This library is considered production ready.  Feedback and feature requests are appreciated.  The API should be considered stable.  There should be very few backwards-incompatible changes outside of major version updates (and only with good reason).

This project uses [Semantic Versioning 2.0.0](http://semver.org).  Accepted pull requests will land on `master`.  Periodically, versions will be tagged from `master`.  You can find all the releases on [the project releases page](https://github.com/dgrijalva/jwt-go/releases).

## More

Documentation can be found [on godoc.org](http://godoc.org/github.com/dgrijalva/jwt-go).

The command line utility included in this project (cmd/jwt) provides a straightforward example of token creation and parsing as well as a useful tool for debugging your own integration.  For a more http centric example, see [this gist](https://gist.github.com/cryptix/45c33ecf0ae54828e63b).
