package jwt

import "sync"

var (
	signingMethods = make(map[string]func() SigningMethod)
	mu             = &sync.RWMutex{}
)

// SigningMethod is an interface that provides a way to sign JWT tokens.
type SigningMethod interface {
	Verify(signingString, signature string, key interface{}) error
	Sign(signingString string, key interface{}) (string, error)
	Alg() string
}

// RegisterSigningMethod registers the "alg" name in the global map.
// This is typically done inside the caller's init function.
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	if GetSigningMethod(alg) != nil {
		panic("Cannot duplicate signing methods.")
	}

	mu.Lock()
	signingMethods[alg] = f
	mu.Unlock()
}

// RemoveSigningMethod removes a signing method from the global map.
func RemoveSigningMethod(alg string) {
	mu.Lock()
	delete(signingMethods, alg)
	mu.Unlock()
}

// GetSigningMethod retrieves a SigningMethod from the global map
// with the given alg.
func GetSigningMethod(alg string) SigningMethod {
	mu.RLock()
	defer mu.RUnlock()
	if a := signingMethods[alg]; a != nil {
		return a()
	}
	return nil
}
