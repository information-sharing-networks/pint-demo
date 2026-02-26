package crypto

// jws.go - Functions for signing and verifying JWS (JSON Web Signature)
//
// Note the DCSA standard requires that JWS compact serialization is used for signing and verifying transport documents
// ... and that the signing process must be performed using a library (this implementation uses github.com/lestrrat-go/jwx/v3)
// the DCSA spec does not say which signing algorithm should be used.
//
// Supported algorithms for verification: RS256, RS384, RS512, PS256, PS384, PS512, EdDSA
// Supported algorithms for signing: RS256, EdDSA
//
// these are low level functions - for standard usage (issuance requests, transfer requests etc)
// you will not need to call these functions directly. See the ebl package for high level functions.

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// JWSHeader represents the header of a JWS token as used in the PINT API
type JWSHeader struct {

	// Algorithm specifies the signing algorithm
	// Supported for verification: RS256, RS384, RS512, PS256, PS384, PS512, EdDSA
	// Supported for signing: RS256, EdDSA
	Algorithm string `json:"alg"`

	// KeyID - this is used to look up the public key in the receiver's key manager
	// per DCSA recommendation this implementation uses the JWK thumbprint of the public key as the key ID
	KeyID string `json:"kid"`
}

// VerifyJWS performs verification for JWS signatures using a KeyProvider.
//
// The function verifies the JWS signature and - if the JWS contains an x5c header -
// the x5c certificate chain.
//
// To determine the trust level based on the certificate type, call DetermineTrustLevel(certChain)
// separately after verification.
//
// Parameters:
//   - JwsToken: JWS compact serialization (header.payload.signature)
//   - keyProvider: KeyProvider that fetches keys based on KID from JWS header
//     (c.f pint.KeyManager which implements this interface)
//   - rootCAs: Root CA pool for certificate validation (nil = use system roots)
//
// Returns:
//   - payload: Verified payload bytes
//   - publicKey: The public key that was used for verification (extracted from keyProvider)
//   - certChain: Certificate chain if x5c was present and valid (nil otherwise)
//   - error: Any validation errors
func VerifyJWS(
	JwsToken string,
	keyProvider jws.KeyProvider,
	rootCAs *x509.CertPool,
) (payload []byte, publicKey any, certChain []*x509.Certificate, err error) {

	if keyProvider == nil {
		return nil, nil, nil, NewInternalError("keyProvider is required")
	}

	if JwsToken == "" {
		return nil, nil, nil, NewInternalError("JwsToken is required")
	}

	// Step 1: Reject JWS where the signature can't be verified against the keyProvider
	//
	// Note using WithKeyProvider eliminates manual KID extraction by automatically
	// selecting the right key during verification:
	//
	// By passing the KeyProvider to jws.Verify, the function will call
	// our KeyProvider.FetchKeys() method, passing a KeySink, signature and
	// message objects. We extract the KID from the signature headers,
	// look up the corresponding key, and add it to the sink using sink.Key().
	// Verify() then uses the key to verify the JWS signature.
	var keyUsed any
	payload, err = jws.Verify([]byte(JwsToken), jws.WithKeyProvider(keyProvider), jws.WithKeyUsed(&keyUsed))
	if err != nil {
		return nil, nil, nil, WrapSignatureError(err, "failed to verify JWS")
	}

	// Step 2: Extract the raw public key that was used for verification.
	// keyUsed may be a jwk.Key (from remote JWKS) or a raw key (from manual config),
	// so we normalise it to a raw key in all cases.
	if jwkKey, ok := keyUsed.(jwk.Key); ok {
		if err := jwk.Export(jwkKey, &publicKey); err != nil {
			return nil, nil, nil, WrapSignatureError(err, "failed to export verification key")
		}
	} else {
		publicKey = keyUsed
	}

	// Step 3: Extract x5c certificate chain (if present)
	certChain, err = ParseX5CFromJWS(JwsToken)
	if err != nil {
		return nil, nil, nil, err
	}

	// If x5c is present, validate the certificate chain and key match
	if certChain != nil {
		// Step 4: Reject JWS if the x5c cert public key does not match the key used for signing
		// This prevents an attacker signing with key A but including a valid x5c
		// certificate chain for organization B, which would cause the verification
		// result to report the wrong organization.
		if err := ValidateX5CMatchesKey(certChain, publicKey); err != nil {
			return nil, nil, nil, err
		}

		// Step 5: Reject JWS if the x5c cert chain is invalid or not trusted
		// This checks:
		// - Certificate chain is valid and trusted by root CAs
		// - Certificates are not expired
		if err := ValidateCertificateChain(certChain, rootCAs); err != nil {
			return nil, nil, nil, err
		}

		// TODO: Certificate revocation status (OCSP/CRL)
	}

	return payload, publicKey, certChain, nil
}

// VerifyJWSEd25519 verifies a Ed25519 JWS compact serialization signature and returns the payload
func VerifyJWSEd25519(JwsToken string, publicKey ed25519.PublicKey) ([]byte, error) {
	// Verify the JWS using EdDSA algorithm
	payload, err := jws.Verify([]byte(JwsToken), jws.WithKey(jwa.EdDSA(), publicKey))
	if err != nil {
		return nil, WrapSignatureError(err, "failed to verify JWS")
	}

	return payload, nil
}

// VerifyJWSRSA verifies a RSA JWS compact serialization signature and returns the payload.
// Supports all RSA signature algorithms: RS256, RS384, RS512 (PKCS#1 v1.5) and PS256, PS384, PS512 (RSA-PSS).
// The algorithm is determined from the JWS header.
func VerifyJWSRSA(JwsToken string, publicKey *rsa.PublicKey) ([]byte, error) {
	// Parse the JWS to extract the algorithm from the header
	msg, err := jws.Parse([]byte(JwsToken))
	if err != nil {
		return nil, WrapSignatureError(err, "failed to parse JWS")
	}

	// Get the algorithm from the first signature
	if len(msg.Signatures()) == 0 {
		return nil, NewValidationError("no signatures found in JWS")
	}
	alg, ok := msg.Signatures()[0].ProtectedHeaders().Algorithm()
	if !ok {
		return nil, NewValidationError("no algorithm specified in JWS header")
	}

	// Verify using the algorithm from the header
	payload, err := jws.Verify([]byte(JwsToken), jws.WithKey(alg, publicKey))
	if err != nil {
		return nil, WrapSignatureError(err, "failed to verify JWS")
	}

	return payload, nil
}

// SignJSON signs a JSON payload using the provided private key and optional certificate chain.
// This function determines the key type and calls the appropriate
// explicit signing function (SignJSONWithEd25519AndX5C, SignJSONWithRSA, etc.).
//
// The privateKey must be either ed25519.PrivateKey or *rsa.PrivateKey.
// The keyID is generated automatically from the public key using JWK thumbprint.
// If certChain is provided and non-empty, it will be included in the x5c header.
//
// Returns the JWS compact serialization string.
func SignJSON(payload []byte, privateKey any, certChain []*x509.Certificate) (string, error) {
	var jws string
	var keyID string
	var err error

	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		// Generate keyID from public key
		publicKey := key.Public().(ed25519.PublicKey)
		keyID, err = GenerateKeyIDFromEd25519Key(publicKey)
		if err != nil {
			return "", WrapInternalError(err, "failed to generate keyID from Ed25519 key")
		}

		// Sign with or without x5c based on cert chain presence
		if len(certChain) > 0 {
			jws, err = SignJSONWithEd25519AndX5C(payload, key, keyID, certChain)
		} else {
			jws, err = SignJSONWithEd25519(payload, key, keyID)
		}

	case *rsa.PrivateKey:
		// Generate keyID from public key
		keyID, err = GenerateKeyIDFromRSAKey(&key.PublicKey)
		if err != nil {
			return "", WrapInternalError(err, "failed to generate keyID from RSA key")
		}

		// Sign with or without x5c based on cert chain presence
		if len(certChain) > 0 {
			jws, err = SignJSONWithRSAAndX5C(payload, key, keyID, certChain)
		} else {
			jws, err = SignJSONWithRSA(payload, key, keyID)
		}

	default:
		return "", NewInternalError("unsupported private key type (expected ed25519.PrivateKey or *rsa.PrivateKey)")
	}

	if err != nil {
		return "", err
	}

	return jws, nil
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
		return "", NewInternalError("keyID is required")
	}
	if len(certChain) == 0 {
		return "", NewInternalError("certificate chain is required")
	}

	// Create protected headers with kid and x5c
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", WrapInternalError(err, "failed to set kid header")
	}

	// Convert certificate chain to cert.Chain format
	x5c := &cert.Chain{}
	for _, c := range certChain {
		// cert.Raw contains the DER-encoded certificate, encode it to base64
		encoded := base64.StdEncoding.EncodeToString(c.Raw)
		if err := x5c.AddString(encoded); err != nil {
			return "", WrapInternalError(err, "failed to add certificate to chain")
		}
	}
	if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
		return "", WrapInternalError(err, "failed to set x5c header")
	}

	// Canonicalize the payload
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", WrapInternalError(err, "failed to canonicalize payload")
	}

	// Sign the payload using EdDSA algorithm
	// Note: Per RFC 7515, the signature covers both the protected header and payload.
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.EdDSA(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", WrapInternalError(err, "failed to sign payload")
	}

	return string(signed), nil
}

// SignJSONWithEd25519 signs payload using Ed25519 algorithm (no x5c header)
func SignJSONWithEd25519(payload []byte, privateKey ed25519.PrivateKey, keyID string) (string, error) {
	if keyID == "" {
		return "", NewInternalError("keyID is required")
	}

	// Create protected headers with kid
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", WrapInternalError(err, "failed to set kid header")
	}

	// Canonicalize the payload
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", WrapInternalError(err, "failed to canonicalize payload")
	}

	// Sign the payload using EdDSA algorithm
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.EdDSA(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", WrapInternalError(err, "failed to sign payload")
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
		return "", NewInternalError("keyID is required")
	}
	if len(certChain) == 0 {
		return "", NewInternalError("certificate chain is required")
	}

	// Create protected headers with kid and x5c
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", WrapInternalError(err, "failed to set kid header")
	}

	// Convert certificate chain to cert.Chain format
	x5c := &cert.Chain{}
	for _, c := range certChain {
		// cert.Raw contains the DER-encoded certificate, encode it to base64
		encoded := base64.StdEncoding.EncodeToString(c.Raw)
		if err := x5c.AddString(encoded); err != nil {
			return "", WrapInternalError(err, "failed to add certificate to chain")
		}
	}
	if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
		return "", WrapInternalError(err, "failed to set x5c header")
	}
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", WrapInternalError(err, "failed to canonicalize payload")
	}

	// Sign the payload using RS256 algorithm
	// The x5c forms part of the JWS protected header and is therefore covered by the signature.
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.RS256(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", WrapInternalError(err, "failed to sign payload")
	}

	return string(signed), nil
}

// SignJSONWithRSA signs payload using RSA algorithm (no x5c header)
func SignJSONWithRSA(payload []byte, privateKey *rsa.PrivateKey, keyID string) (string, error) {
	if keyID == "" {
		return "", NewInternalError("keyID is required")
	}

	// Create protected headers with kid
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return "", WrapInternalError(err, "failed to set kid header")
	}

	// Canonicalize the payload
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", WrapInternalError(err, "failed to canonicalize payload")
	}

	// Sign the payload using RS256 algorithm
	signed, err := jws.Sign(canonical, jws.WithKey(jwa.RS256(), privateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", WrapInternalError(err, "failed to sign payload")
	}

	return string(signed), nil
}

// ParseJWSHeader extracts the header from a JWS without verifying
// use this function if you need to extract the key ID (JWSHeader.KeyID)
// The function returns an error if the header contains something other than the fields in JWSHeader
func ParseJWSHeader(JwsToken string) (JWSHeader, error) {
	// Parse the JWS message
	msg, err := jws.Parse([]byte(JwsToken))
	if err != nil {
		return JWSHeader{}, WrapValidationError(err, "failed to parse JWS")
	}

	// Get the first signature's protected headers
	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return JWSHeader{}, NewValidationError("no signatures found in JWS")
	}

	headers := signatures[0].ProtectedHeaders()

	// Extract algorithm
	alg, ok := headers.Algorithm()
	if !ok {
		return JWSHeader{}, NewValidationError("missing required field: alg")
	}

	// Extract key ID
	kid, ok := headers.KeyID()
	if !ok || kid == "" {
		return JWSHeader{}, NewValidationError("missing required field: kid")
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
