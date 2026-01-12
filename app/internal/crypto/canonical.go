// the DCSA spec requires that JSON documents should be canonicalized per RFC 8785 before signing
// this implementation uses the gowebpki/jcs library to perform this canonicalization
package crypto

import (
	"github.com/gowebpki/jcs"
)

// CanonicalizeJSON converts JSON to canonical form per RFC 8785
// This ensures consistent hashing/signing of JSON documents
//
// If the input is not valid JSON, an error is returned (handled by jcs library).
func CanonicalizeJSON(jsonData []byte) ([]byte, error) {
	return jcs.Transform(jsonData)
}
