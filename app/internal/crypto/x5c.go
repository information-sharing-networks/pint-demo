// x5c.go - Functions for parsing and validating X.509 certificate chains from JWS headers
package crypto

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
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
// Per RFC 7515 Section 4.1.6:
// - The first certificate MUST contain the public key corresponding to the key used to sign the JWS
// - Each subsequent certificate MUST directly certify the one preceding it
// - The certificate containing the public key MAY be followed by additional certificates
//
// This function extracts the raw certificates without validating the JWS signature or the
// certificate chain. Use ValidateCertificateChain() to validate the chain after extraction.
//
// Parameters:
// - jwsString: The JWS token in compact serialization format (header.payload.signature)
//
// Returns:
// - []*x509.Certificate: The parsed certificate chain (leaf first, root last), or nil if x5c is not present
// returns nil if x5c is not present in the JWS header
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
// 1. Validates the certificate chain (expiry, trust chain, signatures)
// 2. Verifies that the certificate's domain matches the expected domain
//
// The DCSA spec requires: "Check that the digital certificate is from the correct party
// (API authentication matches with identity in the certificate)"
//
// This prevents attacks where a valid signed eBL is served from an attacker's domain.
//
// Parameters:
// - certChain: Certificate chain (leaf first, root last) - must be correctly ordered
// - roots: Root CA pool (nil = use system roots for production, custom pool for testing or if a private CA is used)
// - expectedDomain: The domain that must match the certificate (from TLS connection or DCSA registry)
//
// Returns:
// - error: If validation fails or domain doesn't match
func ValidateCertificateChain(certChain []*x509.Certificate, roots *x509.CertPool, expectedDomain string) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	if expectedDomain == "" {
		return fmt.Errorf("empty expected domain")
	}

	// Build intermediate pool from the chain (excluding leaf)
	intermediates := x509.NewCertPool()
	if len(certChain) > 1 {
		for _, cert := range certChain[1:] {
			intermediates.AddCert(cert)
		}
	}

	// Build verify options
	verifyOpts := x509.VerifyOptions{
		Roots:         roots, // nil = use system roots (production), custom pool = testing
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	// Per RFC 7515 Section 4.1.6: "The certificate containing the public key
	// corresponding to the key used to digitally sign the JWS MUST be the first certificate."
	// If the chain is incorrectly ordered, leaf.Verify() will fail during chain validation.
	leaf := certChain[0]
	chains, err := leaf.Verify(verifyOpts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	// TODO: Certificate revocation status (OCSP/CRL)

	// Verify succeeded - log the validated chain(s)
	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	// Verify domain matches (DCSA requirement)
	// Check all SANs (Subject Alternative Names) first (per RFC 6125)
	// TODO - wildcard support?
	domainMatches := slices.Contains(leaf.DNSNames, expectedDomain)

	// Fallback to CN (Common Name) if no SANs present
	if !domainMatches && len(leaf.DNSNames) == 0 {
		domainMatches = leaf.Subject.CommonName == expectedDomain
	}

	if !domainMatches {
		// Build error message with cert's primary domain
		certDomain := "(no domain found)"
		if len(leaf.DNSNames) > 0 {
			certDomain = leaf.DNSNames[0]
		} else if leaf.Subject.CommonName != "" {
			certDomain = leaf.Subject.CommonName
		}
		return fmt.Errorf("certificate domain mismatch: cert contains %q, expected %q", certDomain, expectedDomain)
	}

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
//   - baseDir: The base directory to scope file access (e.g., "./certs" or "testdata/certs")
//   - filename: The filename within the base directory (e.g., "cert.pem")
func ReadCertChainFromPEMFile(baseDir, filename string) ([]*x509.Certificate, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	pemData, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filename, err)
	}

	return ParseCertificateChain(pemData)
}
