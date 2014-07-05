package jwt

import (
	"io/ioutil"
	"strings"
	"testing"
)

var rsaTestData = []struct {
	name        string
	tokenString string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"basic: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestRS256Verify(t *testing.T) {
	key, _ := ioutil.ReadFile("test/sample_key.pub")

	for _, data := range rsaTestData {
		parts := strings.Split(data.tokenString, ".")

		method := GetSigningMethod("RS256")
		err := method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestRS256Sign(t *testing.T) {
	key, _ := ioutil.ReadFile("test/sample_key")

	for _, data := range rsaTestData {
		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			method := GetSigningMethod("RS256")
			sig, err := method.Sign(strings.Join(parts[0:2], "."), key)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}
			if sig != parts[2] {
				t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", data.name, sig, parts[2])
			}
		}
	}
}

func TestRSAKeyParsing(t *testing.T) {
	key, _ := ioutil.ReadFile("test/sample_key")
	pubKey, _ := ioutil.ReadFile("test/sample_key.pub")
	badKey := []byte("All your base are belong to key")
	method := GetSigningMethod("RS256").(*SigningMethodRS256)

	// Test parsePrivateKey
	if _, e := method.parsePrivateKey(key); e != nil {
		t.Errorf("Failed to parse valid private key: %v", e)
	}

	if k, e := method.parsePrivateKey(pubKey); e == nil {
		t.Errorf("Parsed public key as valid private key: %v", k)
	}

	if k, e := method.parsePrivateKey(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}

	// Test parsePublicKey
	if _, e := method.parsePublicKey(pubKey); e != nil {
		t.Errorf("Failed to parse valid public key: %v", e)
	}

	if k, e := method.parsePublicKey(key); e == nil {
		t.Errorf("Parsed private key as valid public key: %v", k)
	}

	if k, e := method.parsePublicKey(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}

}
