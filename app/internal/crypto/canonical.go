// the DCSA spec requires that JSON documents should be canonicalized per RFC 8785 before signing
// this implementation uses the gowebpki/jcs library to perform this canonicalization
//
// this is a low level function - for standard usage (issuance requests, transfer requests etc) you will not need to call this function directly.
package crypto

import (
	"github.com/gowebpki/jcs"
)

// CanonicalizeJSON converts JSON to canonical form per RFC 8785
// This ensures consistent hashing/signing of JSON documents
//
// If the input is not valid JSON, an error is returned (handled by jcs library).
func CanonicalizeJSON(jsonData []byte) ([]byte, error) {

	// TODO keep an eye on jsontext.Value.Canonicalize() - it is a new go stdlib implementation that will be available in go 1.27
	return jcs.Transform(jsonData)
}
