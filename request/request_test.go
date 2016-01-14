package request

// func TestParseRequest(t *testing.T) {
// 	// Bearer token request
// 	for _, data := range jwtTestData {
// 		// FIXME: custom parsers are not supported by this helper.  skip tests that require them
// 		if data.parser != nil {
// 			t.Logf("Skipping [%v].  Custom parsers are not supported by ParseRequest", data.name)
// 			continue
// 		}
//
// 		if data.tokenString == "" {
// 			data.tokenString = makeSample(data.claims)
// 		}
//
// 		r, _ := http.NewRequest("GET", "/", nil)
// 		r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", data.tokenString))
// 		token, err := jwt.ParseFromRequest(r, data.keyfunc)
//
// 		if token == nil {
// 			t.Errorf("[%v] Token was not found: %v", data.name, err)
// 			continue
// 		}
// 		if !reflect.DeepEqual(data.claims, token.Claims) {
// 			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
// 		}
// 		if data.valid && err != nil {
// 			t.Errorf("[%v] Error while verifying token: %v", data.name, err)
// 		}
// 		if !data.valid && err == nil {
// 			t.Errorf("[%v] Invalid token passed validation", data.name)
// 		}
// 	}
// }
