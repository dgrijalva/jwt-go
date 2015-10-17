package jwt_test

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	jwtTestDefaultKey *rsa.PublicKey
	defaultKeyFunc    jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	emptyKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, nil }
	errorKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, fmt.Errorf("error loading key") }
	nilKeyFunc        jwt.Keyfunc = nil
)

var jwtTestData = []struct {
	name        string
	tokenString string
	method 		jwt.SigningMethod
	keyfunc     jwt.Keyfunc
	claims      jwt.MapClaims
	valid       bool
	errors      uint32
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		jwt.SigningMethodRS256,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
	},
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		jwt.SigningMethodRS256,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
	},
	{
		"basic expired",
		"", // autogen
		jwt.SigningMethodRS256,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorExpired,
	},
	{
		"basic nbf",
		"", // autogen
		jwt.SigningMethodRS256,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		jwt.ValidationErrorNotValidYet,
	},
	{
		"expired and nbf",
		"", // autogen
		jwt.SigningMethodRS256,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired,
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		jwt.SigningMethodRS256,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
	},
	{
		"basic nokeyfunc",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		jwt.SigningMethodRS256,
		nilKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
	},
	{
		"basic nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		jwt.SigningMethodRS256,
		emptyKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
	},
	{
		"basic errorkey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		jwt.SigningMethodRS256,
		errorKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
	},
}

func init() {
	if keyData, e := ioutil.ReadFile("test/sample_key.pub"); e == nil {
		if jwtTestDefaultKey, e = jwt.ParseRSAPublicKeyFromPEM(keyData); e != nil {
			panic(e)
		}
	} else {
		panic(e)
	}
}

func makeSample(c jwt.MapClaims) string {
	keyData, e := ioutil.ReadFile("test/sample_key")
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

func TestJWT(t *testing.T) {
	for _, data := range jwtTestData {
		if data.tokenString == "" {
			data.tokenString = makeSample(data.claims)
		}

		token, err := jwt.Parse(jwt.ParseParam{TokenString: data.tokenString, Method: data.method,
			KeyFunc: data.keyfunc,
			Claims: &jwt.MapClaims{}})

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
				if err.(*jwt.ValidationError).Errors != data.errors {
					t.Errorf("[%v] Errors don't match expectation", data.name)
				}

			}
		}
	}
}

func TestParseRequest(t *testing.T) {
	// Bearer token request
	for _, data := range jwtTestData {
		if data.tokenString == "" {
			data.tokenString = makeSample(data.claims)
		}

		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", data.tokenString))
		token, err := jwt.ParseFromRequest(jwt.ParseParam{
			Req: r,
			Method: data.method,
			KeyFunc: data.keyfunc,
			Claims: &jwt.MapClaims{}})

		if token == nil {
			t.Errorf("[%v] Token was not found: %v", data.name, err)
			continue
		}
		if !reflect.DeepEqual(&data.claims, token.Claims) {
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
