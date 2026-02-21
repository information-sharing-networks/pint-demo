// pint package includes the handlers for the PINT API endpoints and the logic to process the requests
// (issuing eBLs, validating signatures, etc.)
//
// **keymanager**
// this package also implements a keymanager for discovering and caching the public keys used to verify PINT JWS signatures
//
// **types**
// the main request/response structs are in api_types.go
//
// **error handling**
// crypto and ebl have their own error types, but they are all mapped to pint error codes and
// returned to the client in the standardized DCSA error response format.
// Use RespondWithErrorResponse() to create and send the error response.
//
// **testing**
// The handlers are tested with end-2-end integration tests - see app/test/integration for details
package pint
