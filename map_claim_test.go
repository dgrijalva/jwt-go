package jwt

import "testing"

func TestMapClaims_VerifyAudience(t *testing.T) {
	var testCases = []struct {
		name         string
		givenClaims  MapClaims
		whenRequired bool
		expect       bool
	}{
		{
			name:         "ok, string, required and aud is matching",
			givenClaims:  MapClaims{"aud": "mysite"},
			whenRequired: true,
			expect:       true,
		},
		{
			name:         "ok, string, optional and aud is matching",
			givenClaims:  MapClaims{"aud": "mysite"},
			whenRequired: false,
			expect:       true,
		},
		{
			name:         "ok, optional and aud is missing",
			givenClaims:  MapClaims{},
			whenRequired: false,
			expect:       true,
		},
		{
			name:         "nok, required and aud is missing",
			givenClaims:  MapClaims{},
			whenRequired: true,
			expect:       false,
		},
		{
			name:         "ok, string, optional and aud is empty",
			givenClaims:  MapClaims{"aud": ""},
			whenRequired: false,
			expect:       true,
		},
		{
			name:         "nok, string, optional and aud is not matching",
			givenClaims:  MapClaims{"aud": "not matching"},
			whenRequired: false,
			expect:       false,
		},
		{
			name:         "nok, string, required and aud is empty",
			givenClaims:  MapClaims{"aud": ""},
			whenRequired: true,
			expect:       false,
		},
		{
			name:         "ok, array, optional and aud is matching",
			givenClaims:  MapClaims{"aud": []string{"not-matching", "yet not matching", "mysite"}},
			whenRequired: false,
			expect:       true,
		},
		{
			name:         "ok, array, optional and aud is empty",
			givenClaims:  MapClaims{"aud": []string{}},
			whenRequired: false,
			expect:       true,
		},
		{
			name:         "nok, array, optional and aud is not matching",
			givenClaims:  MapClaims{"aud": []string{"not-matching"}},
			whenRequired: false,
			expect:       false,
		},
		{
			name:         "ok, array, required and aud is matching",
			givenClaims:  MapClaims{"aud": []string{"not-matching", "yet not matching", "mysite"}},
			whenRequired: true,
			expect:       true,
		},
		{
			name:         "nok, array, required and aud is matching",
			givenClaims:  MapClaims{"aud": []string{"not-matching", "yet not matching"}},
			whenRequired: true,
			expect:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.givenClaims.VerifyAudience("mysite", tc.whenRequired)
			if tc.expect != result {
				t.Error("expected != result")
			}
		})
	}
}
