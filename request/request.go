package request

import (
	"github.com/dgrijalva/jwt-go"
	"strings"
	"net/http"
)

// Try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.
func ParseFromRequest(req *http.Request, keyFunc jwt.Keyfunc) (token *jwt.Token, err error) {

	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			return jwt.Parse(ah[7:], keyFunc)
		}
	}

	// Look for "access_token" parameter
	req.ParseMultipartForm(10e6)
	if tokStr := req.Form.Get("access_token"); tokStr != "" {
		return jwt.Parse(tokStr, keyFunc)
	}

	return nil, jwt.ErrNoTokenInRequest
}
