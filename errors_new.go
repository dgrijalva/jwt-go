// Conditionally adds support for new errors behavior, only where it's the default
// +build go1.13

package jwt

// TODO: add Format and FormatError methods to all error types
//       per: https://go.googlesource.com/proposal/+/master/design/29934-error-values.md
