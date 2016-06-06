package request

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

// Try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.
func ParseFromRequest(req *http.Request, extractor Extractor, keyFunc jwt.Keyfunc) (token *jwt.Token, err error) {
	return ParseFromRequestWithClaims(req, extractor, jwt.MapClaims{}, keyFunc)
}

func ParseFromRequestWithClaims(req *http.Request, extractor Extractor, claims jwt.Claims, keyFunc jwt.Keyfunc) (token *jwt.Token, err error) {
	// Extract token from request
	tokStr, err := extractor.ExtractToken(req)
	if err != nil {
		return nil, err
	}

	return jwt.ParseWithClaims(tokStr, claims, keyFunc)
}
