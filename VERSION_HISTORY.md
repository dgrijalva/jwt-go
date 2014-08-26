## `jwt-go` Version History

#### 1.0.2

* Fixed bug in parsing public keys from certificates
* Added more tests around the parsing of keys for RS256
* Code refactoring in RS256 implementation.  No functional changes

#### 1.0.1

* Fixed panic if RS256 signing method was passed an invalid key

#### 1.0.0

* First versioned release
* API stabilized
* Supports creating, signing, parsing, and validating JWT tokens
* Supports RS256 and HS256 signing methods