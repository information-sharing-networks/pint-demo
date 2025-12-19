// the DCSA standard requires that JWS compact serialization is used for signing and verifying envelopes
// ... and that the signing process MUST be performed using a library (this implementation use github.com/go-jose/go-jose/v4)

// the DCSA spec does not specify which signing algorithm should be used (this implementation uses RS256 or EdDSA)
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// JWSHeader represents the header of a JWS token
type JWSHeader struct {
	Algorithm string `json:"alg"` // "RS256/EdDSA"
	KeyID     string `json:"kid"` // Key ID
}

// SignEd25519 returns a JWS Compact Serialization (Base64URL) string.
// It uses the Ed25519 private key to produce a signature identified as "EdDSA" in the JWS header.
func SignEd25519(payload []byte, privateKey ed25519.PrivateKey, keyID string) (string, error) {

	// todo check keyID format
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}

	signingKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}

	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithHeader("kid", keyID))
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	jwsCompactSerialize, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWS: %w", err)
	}

	return jwsCompactSerialize, nil
}

// SignRSA returns a JWS Compact Serialization (Base64URL) string.
// It uses an RSA Private Key to produce a signature identified as "RS256" in the JWS header.
func SignRSA(payload []byte, privateKey *rsa.PrivateKey, keyID string) (string, error) {

	// todo check keyID format
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}

	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithHeader("kid", keyID))
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	jwsCompactSerialize, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWS: %w", err)
	}

	return jwsCompactSerialize, nil
}

// VerifyEd25519 verifies a Ed25519 JWS compact serialization signature and returns the payload
func VerifyEd25519(jwsString string, publicKey ed25519.PublicKey) ([]byte, error) {

	alg := []jose.SignatureAlgorithm{jose.EdDSA}

	jws, err := jose.ParseSigned(jwsString, alg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	payload, err := jws.Verify(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %w", err)
	}

	return payload, nil
}

// VerifyRSA verifies a RSA JWS compact serialization signature and returns the payload
func VerifyRSA(jwsString string, publicKey *rsa.PublicKey) ([]byte, error) {
	alg := []jose.SignatureAlgorithm{jose.RS256}

	jws, err := jose.ParseSigned(jwsString, alg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	payload, err := jws.Verify(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %w", err)
	}

	return payload, nil
}

// ParseHeader extracts the header from a JWS without verifying
// The function returns an error if the header contains something other than the fields in JWSHeader
func ParseHeader(jwsString string) (JWSHeader, error) {

	// the structure of the jws is Base64URL(Header).Base64URL(Payload).Base64URL(Signature)
	parts := strings.Split(jwsString, ".")
	if len(parts) != 3 {
		return JWSHeader{}, fmt.Errorf("invalid JWS format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return JWSHeader{}, fmt.Errorf("error decoding the header: %w", err)
	}

	var header JWSHeader

	decoder := json.NewDecoder(bytes.NewReader(headerBytes))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&header); err != nil {
		return JWSHeader{}, fmt.Errorf("could not unmarshal header: %w", err)
	}

	// Validate required fields are present
	if header.Algorithm == "" {
		return JWSHeader{}, fmt.Errorf("missing required field: alg")
	}
	if header.KeyID == "" {
		return JWSHeader{}, fmt.Errorf("missing required field: kid")
	}

	return header, nil
}
