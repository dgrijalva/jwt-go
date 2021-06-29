package jwt_test

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/dgrijalva/jwt-go/v4/test"
	"golang.org/x/xerrors"
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
	name        string
	tokenString string
	keyfunc     jwt.Keyfunc
	claims      jwt.Claims
	valid       bool
	errors      []error
	parser      *jwt.Parser
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		nil,
	},
	{
		"basic expired",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		[]error{&jwt.TokenExpiredError{}},
		nil,
	},
	{
		"basic nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		[]error{&jwt.TokenNotValidYetError{}},
		nil,
	},
	{
		"expired and nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		false,
		[]error{&jwt.TokenExpiredError{}, &jwt.TokenNotValidYetError{}},
		nil,
	},
	{
		"expired and nbf with leeway",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 50), "exp": float64(time.Now().Unix() - 50)},
		true,
		nil,
		jwt.NewParser(jwt.WithLeeway(100 * time.Second)),
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{&jwt.InvalidSignatureError{}},
		nil,
	},
	{
		"basic nokeyfunc",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nilKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{&jwt.UnverfiableTokenError{}},
		nil,
	},
	{
		"basic nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		emptyKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{&jwt.InvalidSignatureError{}},
		nil,
	},
	{
		"basic errorkey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		errorKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{&jwt.UnverfiableTokenError{}},
		nil,
	},
	{
		"invalid signing method",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{&jwt.InvalidSignatureError{}},
		jwt.NewParser(jwt.WithValidMethods([]string{"HS256"})),
	},
	{
		"valid signing method",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "HS256"})),
	},
	{
		"JSON Number",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": json.Number("123.4")},
		true,
		nil,
		jwt.NewParser(jwt.WithJSONNumber()),
	},
	{
		"Standard Claims",
		"",
		defaultKeyFunc,
		&jwt.StandardClaims{
			ExpiresAt: jwt.At(time.Now().Add(time.Second * 10).Truncate(time.Second)),
		},
		true,
		nil,
		jwt.NewParser(jwt.WithJSONNumber()),
	},
	{
		"JSON Number - basic expired",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		[]error{&jwt.TokenExpiredError{}},
		jwt.NewParser(jwt.WithJSONNumber()),
	},
	{
		"JSON Number - basic nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		false,
		[]error{&jwt.TokenNotValidYetError{}},
		jwt.NewParser(jwt.WithJSONNumber()),
	},
	{
		"JSON Number - expired and nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		[]error{&jwt.TokenExpiredError{}, &jwt.TokenNotValidYetError{}},
		jwt.NewParser(jwt.WithJSONNumber()),
	},
	{
		"SkipClaimsValidation during token parsing",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		true,
		nil,
		jwt.NewParser(jwt.WithJSONNumber(), jwt.WithoutClaimsValidation()),
	},
	{
		"Audience - Required",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"aud": []interface{}{"foo", "bar"}},
		false,
		[]error{&jwt.InvalidAudienceError{}},
		jwt.NewParser(),
	},
	{
		"Audience - Ignored",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"aud": []interface{}{"foo", "bar"}},
		true,
		nil,
		jwt.NewParser(jwt.WithoutAudienceValidation()),
	},
	{
		"Audience - Pass",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"aud": []interface{}{"foo", "bar"}},
		true,
		nil,
		jwt.NewParser(jwt.WithAudience("foo")),
	},
	{
		"Audience - Fail",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"aud": []interface{}{"foo", "bar"}},
		false,
		[]error{&jwt.InvalidAudienceError{}},
		jwt.NewParser(jwt.WithAudience("baz")),
	},
	{
		"Issuer - Pass",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"iss": "foo"},
		true,
		nil,
		jwt.NewParser(jwt.WithIssuer("foo")),
	},
	{
		"Issuer - Fail",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"iss": "foo"},
		false,
		[]error{&jwt.InvalidIssuerError{}},
		jwt.NewParser(jwt.WithIssuer("bar")),
	},
	{
		"Issuer - Provided but not in claims",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{},
		false,
		[]error{&jwt.InvalidIssuerError{}},
		jwt.NewParser(jwt.WithIssuer("bar")),
	},
	{
		"Issuer - Ignored",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"iss": "foo"},
		true,
		nil,
		jwt.NewParser(),
	},
}

func TestParser_Parse(t *testing.T) {
	privateKey := test.LoadRSAPrivateKeyFromDisk("test/sample_key")

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = test.MakeSampleToken(data.claims, privateKey)
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

		if data.errors != nil {
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
			} else {
				for _, expected := range data.errors {
					var xxx error = expected
					if !xerrors.As(err, &xxx) {
						t.Errorf("[%v] Error is expected to match type %T but doesn't", data.name, expected)
					}
				}
			}
		}
		if data.valid && token.Signature == "" {
			t.Errorf("[%v] Signature is left unpopulated after parsing", data.name)
		}
	}
}

func TestParser_ParseUnverified(t *testing.T) {
	privateKey := test.LoadRSAPrivateKeyFromDisk("test/sample_key")

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = test.MakeSampleToken(data.claims, privateKey)
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
			token, _, err = parser.ParseUnverified(data.tokenString, jwt.MapClaims{})
		case *jwt.StandardClaims:
			token, _, err = parser.ParseUnverified(data.tokenString, &jwt.StandardClaims{})
		}

		if err != nil {
			t.Errorf("[%v] Invalid token", data.name)
		}

		// Verify result matches expectation
		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}

		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
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
