package jwt

import "time"

// ParserOption implements functional options for parser behavior
// see: https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis
type ParserOption func(*Parser)

// WithValidMethods returns the ParserOption for specifying valid signing methods
func WithValidMethods(valid []string) ParserOption {
	return func(p *Parser) {
		p.validMethods = valid
	}
}

// WithJSONNumber returns the ParserOption for using json.Number instead of float64 when parsing
// numeric values. Used most commonly with MapClaims, but it can be useful in some cases with
// structured claims types
func WithJSONNumber() ParserOption {
	return func(p *Parser) {
		p.useJSONNumber = true
	}
}

// WithoutClaimsValidation returns the ParserOption for disabling claims validation
// This does not disable signature validation. Use this if you want intend to implement
// claims validation via other means
func WithoutClaimsValidation() ParserOption {
	return func(p *Parser) {
		p.skipClaimsValidation = true
	}
}

// WithLeeway returns the ParserOption for specifying the
// leeway window.
func WithLeeway(d time.Duration) ParserOption {
	return func(p *Parser) {
		p.leeway = d
	}
}
