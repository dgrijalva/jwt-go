package jwt

var signingMethods = map[string]func() SigningMethod{}

const (
	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
)

// Signing method
type SigningMethod interface {
	Verify(signingString, signature string, key interface{}) error
	Sign(signingString string, key interface{}) (string, error)
	Alg() string
}

// Register the "alg" name and a factory function for signing method.
// This is typically done during init() in the method's implementation
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethods[alg] = f
}

// Get a signing method from an "alg" string
func GetSigningMethod(alg string) (method SigningMethod) {
	if methodF, ok := signingMethods[alg]; ok {
		method = methodF()
	}
	return
}
