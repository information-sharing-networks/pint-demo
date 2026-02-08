// commonhandlers provides general infrastructure HTTP handlers
// (health, version, jwks, docs etc)
//
// admin handlers are also included here as they are not part of the PINT API
// admin_parties.go is for development and testing only - in production
// the parties would be managed by the platform operator and /v3/receiver-validation
// would be used to validate the receiver before transfer.
package commonhandlers
