package request

import (
	"strings"
)

// Extract Authorization header and strip 'Bearer ' from it
var AuthorizationHeaderExtractor = &PostExtractionFilter{
	HeaderExtractor{"Authorization"},
	func(tok string) (string, error) {
		// Should be a bearer token
		if len(tok) > 6 && strings.ToUpper(tok[0:7]) == "BEARER " {
			return tok[7:], nil
		}
		return tok, nil
	},
}

// Extractor for OAuth2 access tokens
var OAuth2Extractor = &MultiExtractor{
	// Look for authorization token first
	AuthorizationHeaderExtractor,
	// Extract access_token from form or GET argument
	&ArgumentExtractor{"access_token"},
}
