package jwt

type SigningMethodNone struct{}

func init() {
	RegisterSigningMethod("none", func() SigningMethod {
		return new(SigningMethodNone)
	})
}

func (m *SigningMethodNone) Alg() string { return "none" }

func (m *SigningMethodNone) Verify(signingString, signature string, key interface{}) (err error) {
	return nil
}

func (m *SigningMethodNone) Sign(signingString string, key interface{}) (string, error) {
	return "", nil
}
