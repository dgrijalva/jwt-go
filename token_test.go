package jwt

import (
	"testing"
)

func TestDecodeSegment(t *testing.T) {
	validSegment := "nxEWX7UD76fRupczm4MWL0B4UQh/tGpjSdWi6z/wlkw="
	_, err := DecodeSegment(validSegment)
	if err != nil {
		t.Errorf("Unable to decode segment %s", validSegment)
	}
}

