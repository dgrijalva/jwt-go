package jwt

import (
	"encoding/json"
	"testing"
)

func TestStandardClaims_VerifyAud(t *testing.T) {
	var testCases = []struct {
		name                 string
		givenToken           string
		whenRequired         bool
		expectUnmarshalError bool
		expect               bool
	}{
		{
			name:         "nok, require, aud is missing",
			givenToken:   `{}`,
			whenRequired: true,
			expect:       false,
		},
		{
			name:         "ok, optional, aud is missing",
			givenToken:   `{}`,
			whenRequired: false,
			expect:       true,
		},
		{
			name:         "ok, required, aud is matching",
			givenToken:   `{"aud": "myaud"}`,
			whenRequired: true,
			expect:       true,
		},
		{
			name:         "ok, optional, aud is matching",
			givenToken:   `{"aud": "myaud"}`,
			whenRequired: false,
			expect:       true,
		},
		{
			name:                 "impossible when aud is array",
			givenToken:           `{"aud": ["site"]}`,
			expectUnmarshalError: true,
		},
		{
			name:                 "impossible when aud is empty array",
			givenToken:           `{"aud": []}`,
			expectUnmarshalError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var claims StandardClaims
			if err := json.Unmarshal([]byte(tc.givenToken), &claims); err != nil {
				if tc.expectUnmarshalError {
					return
				}
				t.Fatal(err)
			}

			result := claims.VerifyAudience("myaud", tc.whenRequired)
			if tc.expect != result {
				t.Fatalf("expect != result")
			}
		})
	}
}
