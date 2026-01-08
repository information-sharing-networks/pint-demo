// jws.go - Functions for signing and verifying JWS (JSON Web Signature)
// Note the DCSA standard requires that JWS compact serialization is used for signing and verifying transport documents
// ... and that the signing process must be performed using a library (this implementation use github.com/go-jose/go-jose/v4)
// the DCSA spec does not say which signing algorithm should be used (this implementation can use either RS256 or EdDSA)
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
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

// CertChainToX5C converts X.509 certificate chain to x5c format
// Returns array of Base64-encoded DER certificates
//
// The x5c header parameter contains the X.509 certificate chain as an array of Base64-encoded DER certificates
// This provides non-repudiation by including the public key certificate in the JWS header
func CertChainToX5C(certChain []*x509.Certificate) []string {
	x5c := make([]string, len(certChain))
	for i, cert := range certChain {
		// cert.Raw contains the DER-encoded certificate
		x5c[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return x5c
}

// SignEd25519WithX5C signs payload and includes x5c certificate chain in JWS header
// This provides non-repudiation per DCSA requirements
//
// Parameters:
// - payload: The data to sign
// - privateKey: Ed25519 private key for signing
// - keyID: Key identifier (kid) for the JWS header
// - certChain: X.509 certificate chain (first cert must match the private key)
//
// Returns:
// - JWS compact serialization string
// - error if signing fails
func SignEd25519WithX5C(payload []byte, privateKey ed25519.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}
	if len(certChain) == 0 {
		return "", fmt.Errorf("certificate chain is required")
	}

	signingKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}

	// Create signer options with kid and x5c headers
	x5c := CertChainToX5C(certChain)
	opts := (&jose.SignerOptions{}).
		WithHeader("kid", keyID).
		WithHeader("x5c", x5c)

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Note: Per RFC 7515, go-jose/v4's Sign function returns a *jose.JSONWebSignature
	// containing a JWS whose signature covers both the protected header and payload.
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

// SignRSAWithX5C signs payload and includes x5c certificate chain in JWS header
// This provides non-repudiation per DCSA requirements
//
// Parameters:
// - payload: The data to sign
// - privateKey: RSA private key for signing
// - keyID: Key identifier (kid) for the JWS header
// - certChain: X.509 certificate chain
//
// The x5c forms part of the JWS protected header and is therefore covered by the signature.
//
// Returns:
// - JWS compact serialization string
// - error if signing fails
func SignRSAWithX5C(payload []byte, privateKey *rsa.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}
	if len(certChain) == 0 {
		return "", fmt.Errorf("certificate chain is required")
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}

	// Create signer options with kid and x5c headers
	x5c := CertChainToX5C(certChain)
	opts := (&jose.SignerOptions{}).
		WithHeader("kid", keyID).
		WithHeader("x5c", x5c)

	signer, err := jose.NewSigner(signingKey, opts)
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

// LoadCertChainFromPEM loads a certificate chain from a PEM file
func LoadCertChainFromPEM(path string) []*x509.Certificate {
	pemData, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read %s: %v", path, err))
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(fmt.Sprintf("failed to parse certificate from %s: %v", path, err))
			}
			certs = append(certs, cert)
		}

		pemData = rest
	}

	if len(certs) == 0 {
		panic(fmt.Sprintf("no certificates found in %s", path))
	}

	return certs
}
