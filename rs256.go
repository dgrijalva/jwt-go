package jwt

type SigningMethodRS256 struct {
}

func init() {
	RegisterSigningMethod("RS256", func() SigningMethod {
		return new(SigningMethodRS256)
	})
}
