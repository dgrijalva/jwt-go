// +build appengine

package jwt_test

import (
	"strings"
	"testing"

	"appengine/aetest"

	"github.com/dgrijalva/jwt-go"
)

// Public/Private key is hardcoded in dev server and found in
// google.appengine.api.app_identity.app_identity_stub

var appEngineTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"AppEngine",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.YgMNm6dQvP0H5ZQC6xheyzCJ7tuz3BYh6YMNVCDNHX58zgbodNVRMgR26hpCtxvnXkz-98Qd_lHcbCeIr8dWLNmt_EOLYXgTTnYoy8qCwnOFj62wnIBamxo684HIDbkoGk3rblbu8LIVA4cPm0_dFnyCcHM1hMao_HhaAb9rxVYA923q2Oi1-MhoVRbpTnru2GNvp8SzWR1KSPFedtxnr9K4iEv8jnuMHIgtvY1FVOxRCTHF6Whqq-YrD0ruqwpEYhMzPPTkqN5KB7EOjg-Am72DPH-eH8aQ40yju-Jb8knVj0IFfbrZl7UhPJ2Gz2WGkAi7aeeUnNIPdUkuS3gd5w",
		"AppEngine",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"AppEngine",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestAppEngineVerify(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, data := range appEngineTestData {
		parts := strings.Split(data.tokenString, ".")

		method := jwt.GetSigningMethod(data.alg)
		err := method.Verify(strings.Join(parts[0:2], "."), parts[2], c)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestAppEngineSign(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, data := range appEngineTestData {
		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			method := jwt.GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), c)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}
			if sig != parts[2] {
				t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", data.name, sig, parts[2])
			}
		}
	}
}
