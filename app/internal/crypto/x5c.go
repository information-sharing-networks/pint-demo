// x5c.go - Functions for parsing and validating X.509 certificate chains from JWS headers
// this implementation of PINT uses x5c certificates for non-repudiation.
package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ParseX5CFromJWS extracts the X.509 certificate chain from a JWS token's x5c header.
//
// The x5c (X.509 Certificate Chain) header parameter contains a chain of one or more
// PKIX certificates [RFC5280]. The certificate chain is represented as a JSON array of
// certificate value strings. Each string in the array is a base64-encoded DER PKIX certificate value.
//
// This function extracts the raw certificates without validating the JWS signature or the
// certificate chain. Use ValidateCertificateChain() to validate the chain after extraction.
//
// Returns the parsed certificate chain, or nil if x5c is not present.
// Error is returned for any parsing errors.
func ParseX5CFromJWS(jwsString string) ([]*x509.Certificate, error) {
	// JWS format: header.payload.signature
	parts := strings.Split(jwsString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode the header (base64url)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWS header: %w", err)
	}

	// Parse header JSON and extract the x5c field
	var header struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWS header JSON: %w", err)
	}

	// x5c is optional
	if len(header.X5C) == 0 {
		return nil, nil
	}

	// Parse each certificate in the chain
	certs := make([]*x509.Certificate, 0, len(header.X5C))
	for i, certStr := range header.X5C {
		// Decode base64 (NB: standard encoding, not URL encoding)
		certDER, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate %d: %w", i, err)
		}

		// Parse DER certificate
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// ValidateCertificateChain validates an X.509 certificate chain and verifies domain binding.
//
// This can be used to validate the content of the x5c header in a JWS received in a PINT message.
// The certificate chain is validated against the expected domain and the trusted root CAs.
//
// Parameters:
//   - certChain: Certificate chain (leaf first, root last)
//   - roots: Root CA pool (nil = system roots, custom pool = testing/private CA)
//   - expectedDomain: Domain from DCSA registry or envelope (e.g., "wavebl.com")
func ValidateCertificateChain(certChain []*x509.Certificate, roots *x509.CertPool, expectedDomain string) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}
	if expectedDomain == "" {
		return fmt.Errorf("empty expected domain")
	}

	// Build intermediate pool from chain (excluding leaf)
	intermediates := x509.NewCertPool()
	if len(certChain) > 1 {
		for _, cert := range certChain[1:] {
			intermediates.AddCert(cert)
		}
	}

	// Validate cert chain against SSL CAs (proves CA-backed identity)
	verifyOpts := x509.VerifyOptions{
		Roots:         roots, // nil = system roots
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	leaf := certChain[0]
	chains, err := leaf.Verify(verifyOpts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}
	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	// Verify domain matches (prevents attacker using substituting their own certificate for the one from the x5c header)
	domainMatches := slices.Contains(leaf.DNSNames, expectedDomain)
	if !domainMatches && len(leaf.DNSNames) == 0 {
		domainMatches = leaf.Subject.CommonName == expectedDomain
	}

	// construct error message
	if !domainMatches {
		certDomain := "(no domain found)"
		if len(leaf.DNSNames) > 0 {
			certDomain = leaf.DNSNames[0]
		} else if leaf.Subject.CommonName != "" {
			certDomain = leaf.Subject.CommonName
		}
		return fmt.Errorf("certificate domain mismatch: cert contains %q, expected %q", certDomain, expectedDomain)
	}

	// TODO: Certificate revocation status (OCSP/CRL)

	return nil
}

// ParseCertificateChain parses one or more X.509 certificates from PEM-encoded data.
// The certificates are returned in the order they appear in the PEM data.
//
// This function is useful for loading certificate chains from files where multiple
// certificates are concatenated in PEM format (common for certificate bundles).
//
// Parameters:
// - pemData: PEM-encoded certificate data (can contain multiple certificates)
//
// Returns:
// - []*x509.Certificate: Slice of parsed certificates in order
// - error: If no certificates are found or parsing fails
func ParseCertificateChain(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	remaining := pemData

	for {
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}

		// Skip non-certificate blocks
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	return certs, nil
}

// ReadCertChainFromPEMFile loads a certificate chain from a PEM file and returns a slice of x509.Certificates.
// The certificates are returned in the order they appear in the PEM file.
//
// Parameters:
//   - path: The file path (e.g., "./certs/cert.pem" or "testdata/certs/fullchain.crt")
func ReadCertChainFromPEMFile(path string) ([]*x509.Certificate, error) {
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory %s: %w", dir, err)
	}
	defer root.Close()

	pemData, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	return ParseCertificateChain(pemData)
}

// ValidateX5CMatchesKey validates that the x5c certificate chain's public
// key matches the signing key received from the sending platform's JWKS
// endpoint or stored certificate.
//
// If the siging key and the public key in the x5c certificate do not match,
// an error has occured on the sending platform and the message containing
// the JWS should be rejected.
//
// Parameters:
//   - certChain: Certificate chain from x5c header (leaf cert first)
//   - publicKey: Sending platform's public key (ed25519.PublicKey or *rsa.PublicKey)
//
// Returns error if:
//   - certChain is empty
//   - publicKey type is unsupported
//   - Public keys don't match
func ValidateX5CMatchesKey(certChain []*x509.Certificate, publicKey any) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Extract public key from leaf certificate
	certPublicKey := certChain[0].PublicKey

	// Compare public keys based on type
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		certKey, ok := certPublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("x5c certificate contains %T key, but expected ed25519.PublicKey", certPublicKey)
		}
		if !key.Equal(certKey) {
			return fmt.Errorf("x5c certificate public key does not match provided Ed25519 key")
		}

	case *rsa.PublicKey:
		certKey, ok := certPublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("x5c certificate contains %T key, but expected *rsa.PublicKey", certPublicKey)
		}
		// Compare RSA keys by checking N and E
		if certKey.N.Cmp(key.N) != 0 || certKey.E != key.E {
			return fmt.Errorf("x5c certificate public key does not match provided RSA key")
		}

	default:
		return fmt.Errorf("unsupported public key type: %T (expected ed25519.PublicKey or *rsa.PublicKey)", publicKey)
	}

	return nil
}
