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
// **state**
// 'envelope' is a request to send an eBL from one platform to another.
// An envelope has a unique transfer chain that is built up over multiple requests and is uniquely identified by the last transfer chain entry signed content checksum.
// In this implementation, envelopes only have two possible states: accepted or not accepted.
// An accepted envelope means that the platform has successfully validated the envelope and all required supporting documents have been received.
//
// The last transfer chain entry's ActionCode describes the sender's intentions for the eBL.
// Accepting an envelope means that the platform has verified the sender's right to perform the described action.
//
// **possession**
// The TRANSFER ActionCode is used when the possessor transfers posession of the eBL to another party.
// Once transfer is accepted the sender can no longer act on the eBL.
//
// Senders can send other action codes to record an event on the eBL transfer chain without transferring possession.
// These are accepted but do not result in a change of possession (the sender remains the possessor)
//
// c.f the transport_document_latest view for a summary of the current state of an eBL
//
// **testing**
// The handlers are tested with end-2-end integration tests - see app/test/integration for details
package pint
