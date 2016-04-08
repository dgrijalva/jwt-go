package jwt_test

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/test"
)

var (
	jwtTestDefaultKey *rsa.PublicKey
	defaultKeyFunc    jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	emptyKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, nil }
	errorKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, fmt.Errorf("error loading key") }
	nilKeyFunc        jwt.Keyfunc = nil
)

func init() {
	jwtTestDefaultKey = test.LoadRSAPublicKeyFromDisk("test/sample_key.pub")
}

var jwtTestData = []struct {
	name        string
	tokenString string
	keyfunc     jwt.Keyfunc
	claims      jwt.MapClaims
	valid       bool
	errors      uint32
	parser      *jwt.Parser
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
	},
	{
		"basic expired",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorExpired,
		nil,
	},
	{
		"basic nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		jwt.ValidationErrorNotValidYet,
		nil,
	},
	{
		"expired and nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired,
		nil,
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic nokeyfunc",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nilKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
		nil,
	},
	{
		"basic nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		emptyKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic errorkey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		errorKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
		nil,
	},
	{
		"invalid signing method",
		"",
		defaultKeyFunc,
		map[string]interface{}{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		&jwt.Parser{ValidMethods: []string{"HS256"}},
	},
	{
		"valid signing method",
		"",
		defaultKeyFunc,
		map[string]interface{}{"foo": "bar"},
		true,
		0,
		&jwt.Parser{ValidMethods: []string{"RS256", "HS256"}},
	},
	{
		"JSON Number",
		"",
		defaultKeyFunc,
		map[string]interface{}{"foo": json.Number("123.4")},
		true,
		0,
		&jwt.Parser{UseJSONNumber: true},
	},
}

func TestParser_Parse(t *testing.T) {
	privateKey := test.LoadRSAPrivateKeyFromDisk("test/sample_key")

	for _, data := range jwtTestData {
		if data.tokenString == "" {
			data.tokenString = test.MakeSampleToken(data.claims, privateKey)
		}

		var token *jwt.Token
		var err error
		if data.parser != nil {
			token, err = data.parser.Parse(data.tokenString, data.keyfunc)
		} else {
			token, err = jwt.Parse(data.tokenString, data.keyfunc)
		}

		if !reflect.DeepEqual(&data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}

		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
		}

		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid token passed validation", data.name)
		}

		if data.errors != 0 {
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
			} else {
				// compare the bitfield part of the error
				if e := err.(*jwt.ValidationError).Errors; e != data.errors {
					t.Errorf("[%v] Errors don't match expectation.  %v != %v", data.name, e, data.errors)
				}
			}
		}
		if data.valid && token.Signature == "" {
			t.Errorf("[%v] Signature is left unpopulated after parsing", data.name)
		}
	}
}

// Helper method for benchmarking various methods
func benchmarkSigning(b *testing.B, method jwt.SigningMethod, key interface{}) {
	t := jwt.New(method)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := t.SignedString(key); err != nil {
				b.Fatal(err)
			}
		}
	})

}
