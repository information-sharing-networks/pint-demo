// the DCSA spec requires that JSON documents should be canonicalized per RFC 8785 before signing
// this implementation uses the gowebpki/jcs library to perform this canonicalization
package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// CanonicalizeJSON converts JSON to canonical form per RFC 8785
// This ensures consistent hashing/signing of JSON documents
//
// The input must be valid JSON. If the input is not valid JSON, an error is returned.
func CanonicalizeJSON(jsonData []byte) ([]byte, error) {
	if !json.Valid(jsonData) {
		return nil, fmt.Errorf("input is not valid JSON")
	}

	return jcs.Transform(jsonData)
}
