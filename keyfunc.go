package jwt

import "fmt"

// Keyfunc is the type passed to Parse methods to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use properties in the
// Header of the token (such as `kid`) to identify which key to use.
//
// Each signing method accepts a different type of key. See the documentation
// for the signing method you're using to ensure you have the correct key type.
// Examples:
// - SigningMethodRSA ('RS256', etc) takes *rsa.PublicKey
// - SigningMethodHSA ('HS256', etc) takes []byte
type Keyfunc func(*Token) (interface{}, error)

// KnownKeyfunc is a helper for generating a Keyfunc from a known
// signing method and key. If your implementation only supports a single signing method
// and key, this is for you.
func KnownKeyfunc(signingMethod SigningMethod, key interface{}) Keyfunc {
	return func(t *Token) (interface{}, error) {
		if signingMethod.Alg() != t.Header["alg"] {
			return nil, fmt.Errorf("unexpected signing method: %v, expected: %v", t.Header["alg"], signingMethod.Alg())
		}
		return key, nil
	}
}
