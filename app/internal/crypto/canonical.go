// the DCSA spec requires that JSON documents should be canonicalized per RFC 8785 before signing
// this implementation uses the gowebpki/jcs library to perform this canonicalization
package crypto

import (
	"github.com/gowebpki/jcs"
)

// CanonicalizeJSON converts JSON to canonical form per RFC 8785
// This ensures consistent hashing/signing of JSON documents
func CanonicalizeJSON(jsonData []byte) ([]byte, error) {
	return jcs.Transform(jsonData)
}
