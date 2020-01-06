package jwt

type FieldDescriptor uint8

const (
	HeadFieldDescriptor   FieldDescriptor = 0
	ClaimsFieldDescriptor FieldDescriptor = 1
)

type SigningOption func(*signingOptions)

type signingOptions struct {
	marshaller TokenMarshaller
}

type TokenMarshaller func(field FieldDescriptor, v interface{}) ([]byte, error)

func WithMarshaller(m TokenMarshaller) SigningOption {
	return func(o *signingOptions) {
		o.marshaller = m
	}
}
