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

var keyFuncError error = fmt.Errorf("error loading key")

var (
	jwtTestDefaultKey *rsa.PublicKey
	defaultKeyFunc    jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	emptyKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, nil }
	errorKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, keyFuncError }
	nilKeyFunc        jwt.Keyfunc = nil
)

func init() {
	jwtTestDefaultKey = test.LoadRSAPublicKeyFromDisk("test/sample_key.pub")
}

var jwtTestData = []struct {
	name         string
	tokenString  string
	tokenOptions []jwt.TokenOption
	keyfunc      jwt.Keyfunc
	claims       jwt.Claims
	valid        bool
	errors       uint32
	parser       *jwt.Parser
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
	},
	{
		"basic expired",
		"", // autogen
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorExpired,
		nil,
	},
	{
		"basic nbf",
		"", // autogen
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		jwt.ValidationErrorNotValidYet,
		nil,
	},
	{
		"expired and nbf",
		"", // autogen
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired,
		nil,
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic nokeyfunc",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nil,
		nilKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
		nil,
	},
	{
		"basic nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nil,
		emptyKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic errorkey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nil,
		errorKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
		nil,
	},
	{
		"invalid signing method",
		"",
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		&jwt.Parser{ValidMethods: []string{"HS256"}},
	},
	{
		"valid signing method",
		"",
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		&jwt.Parser{ValidMethods: []string{"RS256", "HS256"}},
	},
	{
		"JSON Number",
		"",
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": json.Number("123.4")},
		true,
		0,
		&jwt.Parser{UseJSONNumber: true},
	},
	{
		"Standard Claims",
		"",
		nil,
		defaultKeyFunc,
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * 10).Unix(),
		},
		true,
		0,
		&jwt.Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - basic expired",
		"", // autogen
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		jwt.ValidationErrorExpired,
		&jwt.Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - basic nbf",
		"", // autogen
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		false,
		jwt.ValidationErrorNotValidYet,
		&jwt.Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - expired and nbf",
		"", // autogen
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired,
		&jwt.Parser{UseJSONNumber: true},
	},
	{
		"SkipClaimsValidation during token parsing",
		"", // autogen
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		true,
		0,
		&jwt.Parser{UseJSONNumber: true, SkipClaimsValidation: true},
	},
	{
		"basic compress",
		"", // autogen
		[]jwt.TokenOption{jwt.WithCompression()},
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
	},
	{
		"basic decompress",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInppcCI6IkRFRiJ9.H4sIAAAAAAAA_6pWSsvPV7JSSkosUqoFAAAA__8BAAD__-_1K_4NAAAA.pK5ZCz_R70mg_HfmRR2OzgXE6US4FYJY8aRFqCmFUG_6DgAEjQdhPRP4uBDueW3YIwBVGZ8p5oVytuVRvkgx9oso3f6T1aaMhAyfIMrc7h4EhCy6xUPec69j5H6054wel1MYEQwwKqyIuBag2a60Djaaiz430EbiJHQ5nS3vKK8sOcKkLlv2aFKfxipcBc4LEZSDXYQgFV0GJeT-_6oeCoH6FBPgUt_OXf-CGC1EApaY81-j3ich9nYlLwfp5T4ArCd07jTawhXFgSY1K36L4LZL2mZegxPeLVJ1yacRO1uF4hBufurBSbW25FpS4UVl8uOwBTT09Ce3ihcQM37ZRA",
		nil,
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
	},
	{
		"invalid compression algorithm",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInppcCI6Ik9UUiJ9.H4sIAAAAAAAA_6pWSsvPV7JSSkosUqoFAAAA__8BAAD__-_1K_4NAAAA.pK5ZCz_R70mg_HfmRR2OzgXE6US4FYJY8aRFqCmFUG_6DgAEjQdhPRP4uBDueW3YIwBVGZ8p5oVytuVRvkgx9oso3f6T1aaMhAyfIMrc7h4EhCy6xUPec69j5H6054wel1MYEQwwKqyIuBag2a60Djaaiz430EbiJHQ5nS3vKK8sOcKkLlv2aFKfxipcBc4LEZSDXYQgFV0GJeT-_6oeCoH6FBPgUt_OXf-CGC1EApaY81-j3ich9nYlLwfp5T4ArCd07jTawhXFgSY1K36L4LZL2mZegxPeLVJ1yacRO1uF4hBufurBSbW25FpS4UVl8uOwBTT09Ce3ihcQM37ZRA",
		nil,
		defaultKeyFunc,
		jwt.MapClaims{},
		false,
		jwt.ValidationErrorMalformed,
		nil,
	},
}

func TestParser_Parse(t *testing.T) {
	privateKey := test.LoadRSAPrivateKeyFromDisk("test/sample_key")

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = test.MakeSampleToken(data.tokenOptions, data.claims, privateKey)
		}

		// Parse the token
		var token *jwt.Token
		var err error
		var parser = data.parser
		if parser == nil {
			parser = new(jwt.Parser)
		}
		// Figure out correct claims type
		switch data.claims.(type) {
		case jwt.MapClaims:
			token, err = parser.ParseWithClaims(data.tokenString, jwt.MapClaims{}, data.keyfunc)
		case *jwt.StandardClaims:
			token, err = parser.ParseWithClaims(data.tokenString, &jwt.StandardClaims{}, data.keyfunc)
		}

		// Verify result matches expectation
		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}

		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
		}

		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid token passed validation", data.name)
		}

		if (err == nil && !token.Valid) || (err != nil && token.Valid) {
			t.Errorf("[%v] Inconsistent behavior between returned error and token.Valid", data.name)
		}

		if data.errors != 0 {
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
			} else {

				ve := err.(*jwt.ValidationError)
				// compare the bitfield part of the error
				if e := ve.Errors; e != data.errors {
					t.Errorf("[%v] Errors don't match expectation.  %v != %v", data.name, e, data.errors)
				}

				if err.Error() == keyFuncError.Error() && ve.Inner != keyFuncError {
					t.Errorf("[%v] Inner error does not match expectation.  %v != %v", data.name, ve.Inner, keyFuncError)
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
