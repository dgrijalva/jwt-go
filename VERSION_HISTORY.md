## `jwt-go` Version History

#### 2.0.0

* **Compatibility Breaking Changes**
	* `SigningMethodHS256` is now `*SigningMethodHMAC` instead of `type struct`
	* `SigningMethodRS256` is now `*SigningMethodRSA` instead of `type struct`
	* `KeyFunc` now returns `interface{}` instead of `[]byte`
	* `SigningMethod.Sign` now takes `interface{}` instead of `[]byte` for the key
	* `SigningMethod.Verify` now takes `interface{}` instead of `[]byte` for the key
* Renamed type `SigningMethodHS256` to `SigningMethodHMAC`.  Specific sizes are now just instances of this type.
    * Added public package global `SigningMethodHS256`
    * Added public package global `SigningMethodHS384`
    * Added public package global `SigningMethodHS512`
* Renamed type `SigningMethodRS256` to `SigningMethodRSA`.  Specific sizes are now just instances of this type.
    * Added public package global `SigningMethodRS256`
    * Added public package global `SigningMethodRS384`
    * Added public package global `SigningMethodRS512`
* Moved sample private key for HMAC tests from an inline value to a file on disk.  Value is unchanged.
* Refactored the RSA implementation to be easier to read
* Exposed helper methods `ParseRSAPrivateKeyFromPEM` and `ParseRSAPublicKeyFromPEM`

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