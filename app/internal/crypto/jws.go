// jws.go - Functions for signing and verifying JWS (JSON Web Signature)
// Note the DCSA standard requires that JWS compact serialization is used for signing and verifying transport documents
// ... and that the signing process must be performed using a library (this implementation uses github.com/lestrrat-go/jwx/v3)
// the DCSA spec does not say which signing algorithm should be used (this implementation can use either RS256 or EdDSA)
//
// these are low level functions - for standard usage (issuance requests, transfer requests etc)
// you will not need to call these functions directly. See the ebl package for high level functions.
package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// JWSHeader represents the header of a JWS token as used in the PINT API
type JWSHeader struct {

	// Algorithm "RS256/EdDSA"
	Algorithm string `json:"alg"`

	// KeyID - this is used to look up the public key in the receiver's key manager
	// per DCSA recommendation this implementation uses the JWK thumbprint of the public key as the key ID
	KeyID string `json:"kid"`
}

// VerifyEd25519 verifies a Ed25519 JWS compact serialization signature and returns the payload
func VerifyEd25519(jwsString string, publicKey ed25519.PublicKey) ([]byte, error) {
	// Verify the JWS using EdDSA algorithm
	payload, err := jws.Verify([]byte(jwsString), jws.WithKey(jwa.EdDSA(), publicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %w", err)
	}

	return payload, nil
}

// VerifyRSA verifies a RSA JWS compact serialization signature and returns the payload
func VerifyRSA(jwsString string, publicKey *rsa.PublicKey) ([]byte, error) {
	// Verify the JWS using RS256 algorithm
	payload, err := jws.Verify([]byte(jwsString), jws.WithKey(jwa.RS256(), publicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %w", err)
	}

	return payload, nil
}

// VerifyJWS performs verification for JWS signatures received over PINT.
//
// The function verifies the JWS signature and, if the JWS contains an x5c
// header, it also verifies the x5c certificate chain.
//
// To determine the trust level based on the certificate type, call DetermineTrustLevel(certChain)
// separately after verification.
//
// Parameters:
//   - jwsString: JWS compact serialization (header.payload.signature)
//   - publicKey: Public key for signature verification (ed25519.PublicKey or *rsa.PublicKey)
//   - expectedDomain: Expected sender domain (e.g., "wavebl.com"). Required if x5c is present.
//   - rootCAs: Root CA pool for certificate validation (nil = use system roots)
//
// Returns:
//   - payload: Verified payload bytes
//   - certChain: Certificate chain if x5c was present and valid (nil otherwise)
//   - error: Any validation errors
func VerifyJWS(
	jwsString string,
	publicKey any,
	expectedDomain string,
	rootCAs *x509.CertPool,
) (payload []byte, certChain []*x509.Certificate, err error) {

	if publicKey == nil {
		return nil, nil, fmt.Errorf("public key is required")
	}

	if expectedDomain == "" {
		return nil, nil, fmt.Errorf("expected domain is required")
	}

	if jwsString == "" {
		return nil, nil, fmt.Errorf("jwsString is required")
	}

	// Step 1: Verify the JWS signature
	// This proves the signer owns the private key corresponding to publicKey
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		payload, err = VerifyEd25519(jwsString, key)
	case *rsa.PublicKey:
		payload, err = VerifyRSA(jwsString, key)
	default:
		return nil, nil, fmt.Errorf("unsupported public key type: %T (expected ed25519.PublicKey or *rsa.PublicKey)", publicKey)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Step 2: Extract x5c certificate chain (if present)
	certChain, err = ParseX5CFromJWS(jwsString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse x5c: %w", err)
	}

	// no x5c present (x5c is optional, so this is not an error)
	if certChain == nil {
		return payload, nil, nil
	}

	// Step 3: Validate x5c public key matches the signing key
	if err = ValidateX5CMatchesKey(certChain, publicKey); err != nil {
		return nil, nil, fmt.Errorf("x5c public key does not match signing key: %w", err)
	}

	// Step 4: Validate certificate chain (CA trust, expiry, domain)
	// This checks:
	// - Certificate chain is valid and trusted by root CAs
	// - Certificates are not expired
	// - Domain in certificate matches expected domain
	if err = ValidateCertificateChain(certChain, rootCAs, expectedDomain); err != nil {
		return nil, nil, fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return payload, certChain, nil
}

// ParseHeader extracts the header from a JWS without verifying
// The function returns an error if the header contains something other than the fields in JWSHeader
func ParseHeader(jwsString string) (JWSHeader, error) {
	// Parse the JWS message
	msg, err := jws.Parse([]byte(jwsString))
	if err != nil {
		return JWSHeader{}, fmt.Errorf("failed to parse JWS: %w", err)
	}

	// Get the first signature's protected headers
	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return JWSHeader{}, fmt.Errorf("no signatures found in JWS")
	}

	headers := signatures[0].ProtectedHeaders()

	// Extract algorithm
	alg, ok := headers.Algorithm()
	if !ok {
		return JWSHeader{}, fmt.Errorf("missing required field: alg")
	}

	// Extract key ID
	kid, ok := headers.KeyID()
	if !ok || kid == "" {
		return JWSHeader{}, fmt.Errorf("missing required field: kid")
	}

	return JWSHeader{
		Algorithm: alg.String(),
		KeyID:     kid,
	}, nil
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

// SignJSONWithEd25519AndX5C signs payload and includes x5c certificate chain in JWS header.
// This provides non-repudiation per DCSA requirements.
//
// Parameters:
// - Payload: json payload (will be canonicalized by the function below)
// - privateKey: Ed25519 private key for signing
// - keyID: Key identifier (kid) for the JWS header (DCSA recommends using the JWK thumbprint)
// - certChain: X.509 certificate chain (first cert must match the private key)
func SignJSONWithEd25519AndX5C(payload []byte, privateKey ed25519.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}
	if len(certChain) == 0 {
		return "", fmt.Errorf("certificate chain is required")
	}

	// Create protected headers with kid and x5c
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", fmt.Errorf("failed to set kid header: %w", err)
	}

	// Convert certificate chain to cert.Chain format
	x5c := &cert.Chain{}
	for _, c := range certChain {
		// cert.Raw contains the DER-encoded certificate, encode it to base64
		encoded := base64.StdEncoding.EncodeToString(c.Raw)
		if err := x5c.AddString(encoded); err != nil {
			return "", fmt.Errorf("failed to add certificate to chain: %w", err)
		}
	}
	if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
		return "", fmt.Errorf("failed to set x5c header: %w", err)
	}

	// Canonicalize the payload
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize payload: %w", err)
	}

	// Sign the payload using EdDSA algorithm
	// Note: Per RFC 7515, the signature covers both the protected header and payload.
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.EdDSA(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return string(signed), nil
}

// SignJSONWithEd25519 signs payload using Ed25519 algorithm (no x5c header)
func SignJSONWithEd25519(payload []byte, privateKey ed25519.PrivateKey, keyID string) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}

	// Create protected headers with kid
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", fmt.Errorf("failed to set kid header: %w", err)
	}

	// Canonicalize the payload
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize payload: %w", err)
	}

	// Sign the payload using EdDSA algorithm
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.EdDSA(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return string(signed), nil
}

// SignJSONWithRSAAndX5C signs payload and includes x5c certificate chain in JWS header.
// This provides non-repudiation per DCSA requirements.
//
// Parameters:
// - payload: JSON to sign (will be canonicalized below)
// - privateKey: RSA private key for signing
// - keyID: Key identifier (kid) for the JWS header
// - certChain: X.509 certificate chain
func SignJSONWithRSAAndX5C(payload []byte, privateKey *rsa.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}
	if len(certChain) == 0 {
		return "", fmt.Errorf("certificate chain is required")
	}

	// Create protected headers with kid and x5c
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", fmt.Errorf("failed to set kid header: %w", err)
	}

	// Convert certificate chain to cert.Chain format
	x5c := &cert.Chain{}
	for _, c := range certChain {
		// cert.Raw contains the DER-encoded certificate, encode it to base64
		encoded := base64.StdEncoding.EncodeToString(c.Raw)
		if err := x5c.AddString(encoded); err != nil {
			return "", fmt.Errorf("failed to add certificate to chain: %w", err)
		}
	}
	if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
		return "", fmt.Errorf("failed to set x5c header: %w", err)
	}
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize payload: %w", err)
	}

	// Sign the payload using RS256 algorithm
	// The x5c forms part of the JWS protected header and is therefore covered by the signature.
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.RS256(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return string(signed), nil
}

// SignJSONWithRSA signs payload using RSA algorithm (no x5c header)
func SignJSONWithRSA(payload []byte, privateKey *rsa.PrivateKey, keyID string) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}

	// Create protected headers with kid
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", fmt.Errorf("failed to set kid header: %w", err)
	}

	// Canonicalize the payload
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize payload: %w", err)
	}

	// Sign the payload using RS256 algorithm
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.RS256(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return string(signed), nil
}
