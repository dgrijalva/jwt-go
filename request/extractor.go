package request

import (
	"errors"
	"net/http"
)

// Errors
var (
	ErrNoTokenInRequest = errors.New("no token present in request")
)

// Interface for extracting a token from an HTTP request
type Extractor interface {
	ExtractToken(*http.Request) (string, error)
}

// Extract token from headers
type HeaderExtractor []string

func (e HeaderExtractor) ExtractToken(req *http.Request) (string, error) {
	// loop over header names and return the first one that contains data
	for _, header := range e {
		if ah := req.Header.Get(header); ah != "" {
			return ah, nil
		}
	}
	return "", ErrNoTokenInRequest
}

// Extract token from request args
type ArgumentExtractor []string

func (e ArgumentExtractor) ExtractToken(req *http.Request) (string, error) {
	// Make sure form is parsed
	req.ParseMultipartForm(10e6)

	// loop over arg names and return the first one that contains data
	for _, arg := range e {
		if ah := req.Form.Get(arg); ah != "" {
			return ah, nil
		}
	}

	return "", ErrNoTokenInRequest
}

// Tries extractors in order until one works or an error occurs
type MultiExtractor []Extractor

func (e MultiExtractor) ExtractToken(req *http.Request) (string, error) {
	// loop over header names and return the first one that contains data
	for _, extractor := range e {
		if tok, err := extractor.ExtractToken(req); tok != "" {
			return tok, nil
		} else if err != ErrNoTokenInRequest {
			return "", err
		}
	}
	return "", ErrNoTokenInRequest
}

// Wrap an Extractor in this to post-process the value before it's handed off
type PostExtractionFilter struct {
	Extractor
	Filter func(string) (string, error)
}

func (e *PostExtractionFilter) ExtractToken(req *http.Request) (string, error) {
	if tok, err := e.Extractor.ExtractToken(req); tok != "" {
		return e.Filter(tok)
	} else {
		return "", err
	}
}
