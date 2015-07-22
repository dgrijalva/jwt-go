A [go](http://www.golang.org) (or 'golang' for search engine friendliness) implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-jones-json-web-token.html)

[![Build Status](https://travis-ci.org/dgrijalva/jwt-go.svg?branch=master)](https://travis-ci.org/dgrijalva/jwt-go)

**NOTICE:** A vulnerability in JWT was [recently published](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/).  As this library doesn't force users to validate the `alg` is what they expected, it's possible your usage is effected.  There will be an update soon to remedy this, and it will likey require backwards-incompatible changes to the API.  In the short term, please make sure your implementation verifies the `alg` is what you expect.

## Migration Guide from v2 -> v3

Added the ability to supply a typed object for the claims section of the token.

Unfortunately this requires a breaking change. A few new methods were added to support this,
and the old default of `map[string]interface{}` was changed to `jwt.MapClaim`.

The old example for creating a token looked like this..

```go
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["foo"] = "bar"
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
```

is now directly mapped to...

```go
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaim)
	claims["foo"] = "bar"
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
```

However, we added a helper `jwt.NewWithClaims` which accepts a claims object.

Any type can now be used as the claim object for inside a token so long as it implements the interface `jwt.Claims`.

So, we added an additional claim type `jwt.StandardClaims` was added.
This is intended to be used as a base for creating your own types from,
and includes a few helper functions for verifying the claims defined [here](https://tools.ietf.org/html/rfc7519#section-4.1).

```go
	claims := jwt.StandardClaims{
		Audience: "myapi"
		ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
```

On the other end of usage all of the `jwt.Parse` and friends got a `WithClaims` suffix added to them.

```go
	token, err := jwt.Parse(token, keyFunc)
	claims := token.Claims.(jwt.MapClaim)
	//like you used to..
	claims["foo"]
	claims["bar"]
```

New method usage:
```go
	token, err := jwt.ParseWithClaims(token, keyFunc, &jwt.StandardClaims{})
	claims := token.Claims.(jwt.StandardClaims)
	fmt.Println(claims.IssuedAt)
```

## What the heck is a JWT?

In short, it's a signed JSON object that does something useful (for example, authentication).  It's commonly used for `Bearer` tokens in Oauth 2.  A token is made of three parts, separated by `.`'s.  The first two parts are JSON objects, that have been [base64url](http://tools.ietf.org/html/rfc4648) encoded.  The last part is the signature, encoded the same way.

The first part is called the header.  It contains the necessary information for verifying the last part, the signature.  For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit.  It's called the Claims and contains the actual stuff you care about.  Refer to [the RFC](http://self-issued.info/docs/draft-jones-json-web-token.html) for information about reserved keys and the proper way to add your own.

## What's in the box?

This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are RSA256 and HMAC SHA256, though hooks are present for adding your own.

## Parse and Verify

Parsing and verifying tokens is pretty straight forward.  You pass in the token and a function for looking up the key.  This is done as a callback since you may need to parse the token to find out what signing method and key was used.

```go
	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaim{
		"foo": "bar",
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	})
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(mySigningKey)
```

## Project Status & Versioning

This library is considered production ready.  Feedback and feature requests are appreciated.  The API should be considered stable.  There should be very few backwards-incompatible changes outside of major version updates (and only with good reason).

This project uses [Semantic Versioning 2.0.0](http://semver.org).  Accepted pull requests will land on `master`.  Periodically, versions will be tagged from `master`.  You can find all the releases on [the project releases page](https://github.com/dgrijalva/jwt-go/releases).

While we try to make it obvious when we make breaking changes, there isn't a great mechanism for pushing announcements out to users.  You may want to use this alternative package include: `gopkg.in/dgrijalva/jwt-go.v2`.  It will do the right thing WRT semantic versioning.

## More

Documentation can be found [on godoc.org](http://godoc.org/github.com/dgrijalva/jwt-go).

The command line utility included in this project (cmd/jwt) provides a straightforward example of token creation and parsing as well as a useful tool for debugging your own integration.  For a more http centric example, see [this gist](https://gist.github.com/cryptix/45c33ecf0ae54828e63b).
