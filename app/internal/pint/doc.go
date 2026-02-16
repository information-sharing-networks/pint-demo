// the pint package provides the PINT API implementation for the pint-demo app.
// it includes the handlers for the PINT API endpoints and the logic to process the requests
// (issuing eBLs, validating signatures, etc.)
// .. and also the keymanager for discovering and caching public keys used to verify PINT JWS signatures
//
// Notes on error handling:
// crypto, ebl and pint have their own error types, but they are all mapped to the same DCSA error codes
// c.f. the error_response.go file for the mapping logic.
package pint
