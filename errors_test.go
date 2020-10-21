package jwt

import "testing"

func TestErrorWrapper_Unwrap(t *testing.T) {
	err1 := &UnverfiableTokenError{}
	err2 := &InvalidSignatureError{}
	err1.Wrap(err2)
	unwrapped := err1.Unwrap()
	if unwrapped != err2 {
		t.Errorf("Unwrapped error was not expected value.")
	}
}
