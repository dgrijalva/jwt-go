package jwt

// FieldDescriptor provides context to TokenMarshaller and TokenUnmarshaller
// This is to enable the marshaller to treat the head and body differently
type FieldDescriptor uint8

// Constants describe which field is being processed by custom Marshaller
const (
	HeadFieldDescriptor   FieldDescriptor = 0
	ClaimsFieldDescriptor FieldDescriptor = 1
)

// SigningOption can be passed to signing related methods on Token to customize behavior
type SigningOption func(*signingOptions)

type signingOptions struct {
	marshaller TokenMarshaller
}

// TokenMarshaller is the interface you must implement to provide custom JSON marshalling
// behavior. It is the same as json.Marshal with the addition of the FieldDescriptor.
// The field value will let your marshaller know which field is being processed.
// This is to facilitate things like compression, where you wouldn't want to compress
// the head.
type TokenMarshaller func(field FieldDescriptor, v interface{}) ([]byte, error)

// WithMarshaller returns a SigningOption that will tell the signing code to use your custom Marshaller
func WithMarshaller(m TokenMarshaller) SigningOption {
	return func(o *signingOptions) {
		o.marshaller = m
	}
}
