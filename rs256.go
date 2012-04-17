package jwt

type SigningMethodRS256 struct {
}

func init() {
	RegisterSigningMethod("RS256", func() SigningMethod {
		return new(SigningMethodRS256)
	})
}

func (m *SigningMethodRS256) Verify(signingString, signature string, key []byte)error {
	return nil
}

func (m *SigningMethodRS256) Sign(token, key []byte)error {
	return nil
}