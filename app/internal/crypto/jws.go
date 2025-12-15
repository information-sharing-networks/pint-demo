package crypto

import (
	"crypto/rsa"
	"fmt"
)

// JWSHeader represents the header of a JWS token
type JWSHeader struct {
	Algorithm string `json:"alg"` // "RS256"
	Type      string `json:"typ"` // "JWT"
	KeyID     string `json:"kid,omitempty"`
}

// SignJWS creates a JWS compact serialization signature
// TODO: Implement JWS signing using github.com/go-jose/go-jose/v3
// - Create a signer with RS256 algorithm
// - Sign the payload with the private key
// - Return compact serialization format: header.payload.signature
//
// Example usage:
//
//	payload := []byte(`{"foo":"bar"}`)
//	signature, err := SignJWS(payload, privateKey, "platform-a-key-1")
//
// Reference: https://github.com/go-jose/go-jose
// Example:
//
//	import "github.com/go-jose/go-jose/v3"
//
//	signer, err := jose.NewSigner(
//	    jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
//	    &jose.SignerOptions{}.WithType("JWT").WithHeader("kid", keyID),
//	)
//	jws, err := signer.Sign(payload)
//	return jws.CompactSerialize()
func SignJWS(payload []byte, privateKey *rsa.PrivateKey, keyID string) (string, error) {
	// TODO: Implement JWS signing
	// Hint: Use jose.NewSigner() and jws.CompactSerialize()
	return "", fmt.Errorf("not implemented")
}

// VerifyJWS verifies a JWS signature and returns the payload
// TODO: Implement JWS verification using github.com/go-jose/go-jose/v3
// - Parse the JWS compact serialization
// - Verify the signature using the public key
// - Return the original payload if verification succeeds
//
// Example usage:
//
//	payload, err := VerifyJWS(signature, publicKey)
//
// Reference: https://github.com/go-jose/go-jose
// Example:
//
//	import "github.com/go-jose/go-jose/v3"
//
//	jws, err := jose.ParseSigned(signature)
//	payload, err := jws.Verify(publicKey)
//	return payload
func VerifyJWS(signature string, publicKey *rsa.PublicKey) ([]byte, error) {
	// TODO: Implement JWS verification
	// Hint: Use jose.ParseSigned() and jws.Verify()
	return nil, fmt.Errorf("not implemented")
}

// ParseJWSHeader extracts the header from a JWS without verifying
// TODO: Implement JWS header parsing
// - Decode the first part of the compact serialization (before first '.')
// - Base64 decode it
// - Unmarshal JSON into JWSHeader struct
// - This is useful for extracting the key ID before verification
//
// Example usage:
//
//	header, err := ParseJWSHeader(signature)
//	keyID := header.KeyID
func ParseJWSHeader(signature string) (*JWSHeader, error) {
	// TODO: Implement header parsing
	return nil, fmt.Errorf("not implemented")
}
