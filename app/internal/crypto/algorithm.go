// algorithm.go defines the signing algorithms supported by the pint-demo app
// Note that the DCSA PINT specification does not dictate which algorithm should be used.
package crypto

// Algorithm specifies which signing algorithm to use for JWS signatures
type Algorithm string

const (
	// AlgorithmEd25519: EdDSA with Ed25519 curve (recommended for new implementations)
	AlgorithmEd25519 Algorithm = "EdDSA"

	// AlgorithmRSA: RS256 (RSA with SHA-256)
	AlgorithmRSA Algorithm = "RS256"
)
