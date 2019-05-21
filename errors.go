package jwt

import (
	"errors"
	"fmt"
	"time"
)

// Copied from xerrors, for compatibility without requiring the xerrors package
type errorPrinter interface {
	Print(args ...interface{})
	Printf(format string, args ...interface{})
	Detail() bool
}

// Error constants
var (
	ErrInvalidKey      = errors.New("key is invalid")
	ErrInvalidKeyType  = NewInvalidKeyTypeError("", "")
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")
)

type InvalidKeyTypeError struct {
	expected, received string
}

func (e *InvalidKeyTypeError) Error() string {
	if e.expected == "" && e.received == "" {
		return "key is of invalid type"
	}
	return fmt.Sprintf("key is of invalid type: expected %v, received %v", e.Unwrap(), e.expected, e.received)
}

func (e *InvalidKeyTypeError) Format(f fmt.State, c rune) {
	if c == '+' {
		f.Write([]byte(e.Error()))
	} else {
		f.Write([]byte(ErrInvalidKeyType.Error()))
	}
}

func (e *InvalidKeyTypeError) Unwrap() error {
	return ErrInvalidKeyType
}

func NewInvalidKeyTypeError(expected, received string) error {
	return &InvalidKeyTypeError{expected, received}
}

// The errors that might occur when parsing and validating a token
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed

	// Standard Claim validation errors
	ValidationErrorAudience      // AUD validation failed
	ValidationErrorExpired       // EXP validation failed
	ValidationErrorIssuer        // ISS validation failed
	ValidationErrorNotValidYet   // NBF validation failed
	ValidationErrorID            // JTI validation failed
	ValidationErrorClaimsInvalid // Generic claims validation error
)

// NewValidationError is a helper for constructing a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText,
		Errors: errorFlags,
	}
}

// ValidationError is the error from Parse if token is not valid
type ValidationError struct {
	inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text
}

// Validation error is an error type
func (e ValidationError) Error() string {
	if e.inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

// Unwrap implements xerrors.Wrapper
func (e ValidationError) Unwrap() error {
	return e.inner
}

// No errors
func (e *ValidationError) valid() bool {
	return e.Errors == 0
}

// ExpiredError allows the caller to know the delta between now and the expired time and the unvalidated claims.
// A client system may have a bug that doesn't refresh a token in time, or there may be clock skew so this information can help you understand.
type ExpiredError struct {
	Now       time.Time
	ExpiredBy time.Duration
	Claims
}

func (e *ExpiredError) Error() string {
	return "Token is expired"
}

type MultiError []error
