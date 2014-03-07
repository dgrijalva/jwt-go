package jwt

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"
)

var jwtTestData = []struct {
	name            string
	tokenString     string
	claims          map[string]interface{}
	valid           bool
	validationError *ValidationError
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		map[string]interface{}{"foo": "bar"},
		true,
		nil,
	},
	{
		"basic expired",
		"", // autogen
		map[string]interface{}{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		&ValidationError{Expired: true},
	},
	{
		"basic nbf",
		"", // autogen
		map[string]interface{}{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		&ValidationError{NotValidYet: true},
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		map[string]interface{}{"foo": "bar"},
		false,
		&ValidationError{SignatureInvalid: true},
	},
}

func makeSample(c map[string]interface{}) string {
	file, _ := os.Open("test/sample_key")
	buf := new(bytes.Buffer)
	io.Copy(buf, file)
	key := buf.Bytes()
	file.Close()

	token := New(GetSigningMethod("RS256"))
	token.Claims = c
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

func TestJWT(t *testing.T) {
	file, _ := os.Open("test/sample_key.pub")
	buf := new(bytes.Buffer)
	io.Copy(buf, file)
	key := buf.Bytes()
	file.Close()

	for _, data := range jwtTestData {
		if data.tokenString == "" {
			data.tokenString = makeSample(data.claims)
		}

		token, err := Parse(data.tokenString, func(t *Token) ([]byte, error) { return key, nil })

		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid token passed validation", data.name)
		}
		if data.validationError != nil {
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
			} else {
				// perform deep equal without the string bit
				err.(*ValidationError).err = ""
				if !reflect.DeepEqual(data.validationError, err) {
					t.Errorf("[%v] Errors don't match expectation", data.name)
				}

			}
		}
	}
}

func TestParseRequest(t *testing.T) {
	file, _ := os.Open("test/sample_key.pub")
	buf := new(bytes.Buffer)
	io.Copy(buf, file)
	key := buf.Bytes()
	file.Close()

	// Bearer token request
	for _, data := range jwtTestData {
		if data.tokenString == "" {
			data.tokenString = makeSample(data.claims)
		}

		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", data.tokenString))
		token, err := ParseFromRequest(r, func(t *Token) ([]byte, error) { return key, nil })

		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid token passed validation", data.name)
		}
	}
}
