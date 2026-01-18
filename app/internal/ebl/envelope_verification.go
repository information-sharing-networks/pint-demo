// envelope_verification.go provides high-level functions for verifying DCSA EBL_PINT API envelope transfers.
//
// the verification process is as follows:
// 1. Check envelope structure for required fields
// 2. Verify x5c certificate chain if present (optional but recommended for non-repudiation)
// 3. Determine trust level (based on the type of certificate presented)
// 4. Verify envelope manifest JWS signature and extract the manifest
// 5. Verify the transport document JSON checksum matches the manifest
// 6. Verify transfer chain integrity
// 7. Verify transport document checksums match between manifest and last entry (anti-replay protection)
//
// # Signature Verification Process
//
// The public key used for verification is provided as input - in production
// it should be fetched from the sender's JWKS endpoint (looked up by kid from JWS header)
// or - if keys were exchanged out of band - obtained from the services' trust store.
//
// 1: Decode the JWS and verify signature
//
//	Parse JWS, extract kid from header, and verify signature using provided public key
//
// 2: If x5c is present in the JWS header, validate the certificate chain
//
//	(see crypto.validateX5C for details on the validation process)
//
// 3: Determine trust level  (see crypto.DetermineTrustLevel)
//
// 4: Validate checksums and payload integrity
//
//	a) Verify transport document checksum matches manifest
//	b) Verify last transfer chain entry checksum matches manifest
//	c) Verify anti-replay protection (checksums match between manifest and last entry)
//	d) Verify full transfer chain integrity (all entries validated)
//
// # Platform Identification
//
// Platform identification is achieved through JWS signature and doman verification.
// The domain is determined from the SSL cert and verified against the DCSA registry.
//
// # Trust Hierarchy
// This app implements a trust hierarchy based on certificate validation level (levels 1-3 - see below comments)
//
// # Key ID (kid) Usage
// This app uses the JWK thumbprint of the signing public key as the key ID.

package ebl

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// TODO review domain logic validation - should this be done based on the ssl certificate common name?

// EnvelopeVerificationInput contains the data needed to verify an envelope transfer.
type EnvelopeVerificationInput struct {

	// Envelope is the complete eBL Envelope received from POST /v3/envelopes
	Envelope *crypto.EblEnvelope

	// ExpectedSenderDomain is the expected sender's domain (e.g., "wavebl.com")
	// Used to validate the JWK endpoint domain or stored certificate domain matches
	// the expected sender.
	// The sender domain should be on the DCSA registry of approved platforms.
	ExpectedSenderDomain string

	// RootCAs is the root CA pool for certificate validation
	// nil = use system roots (typically used for production), custom pool = testing/private CA
	RootCAs *x509.CertPool

	// PublicKey is the ed25519.PublicKey or *rsa.PublicKey to use for verification of the JWS signature
	// in production this will be fetched from the public JWK set of the sender
	// (looked up based on the key ID in the JWS header).
	PublicKey any
}

// EnvelopeVerificationResult contains the results of envelope verification.
type EnvelopeVerificationResult struct {

	// Manifest is the verified EnvelopeManifest extracted from envelope.envelopeManifestSignedContent
	Manifest *crypto.EnvelopeManifest

	// LastTransferChainEntry is the verified last entry in the transfer chain
	LastTransferChainEntry *crypto.EnvelopeTransferChainEntry

	// TransportDocumentChecksum is the computed checksum of the transport document
	TransportDocumentChecksum string

	// TrustLevel indicates the trust level achieved by the signature
	TrustLevel crypto.TrustLevel

	// CertificateSubject contains the certificate subject from JWKS or stored cert (or x5c if present)
	CertificateSubject string

	// CertificateOrganization contains the organization name (if OV/EV certificate)
	CertificateOrganization string
}

// VerifyEnvelopeTransfer verifies of an incoming envelope transfer request.
//
// Returns the EnvelopeVerificationResult with extracted data or an error if verification fails
func VerifyEnvelopeTransfer(input EnvelopeVerificationInput) (*EnvelopeVerificationResult, error) {
	result := &EnvelopeVerificationResult{}

	// Step 1: Validate envelope structure (required fields)
	if err := input.Envelope.Validate(); err != nil {
		return nil, fmt.Errorf("envelope validation failed: %w", err)
	}

	// Step 2: Validate x5c (if present)
	certChain, err := validateX5C(
		string(input.Envelope.EnvelopeManifestSignedContent),
		input.PublicKey,
		input.ExpectedSenderDomain,
		input.RootCAs,
	)
	if err != nil {
		return nil, fmt.Errorf("BSIG: x5c validation failed: %w", err)
	}

	// Step 3: Determine trust level for this signature
	trustLevel, err := crypto.DetermineTrustLevel(string(input.Envelope.EnvelopeManifestSignedContent))
	if err != nil {
		return nil, fmt.Errorf("failed to determine trust level: %w", err)
	}
	result.TrustLevel = trustLevel

	// Extract certificate information if x5c was present and valid
	if len(certChain) > 0 {
		result.CertificateSubject = certChain[0].Subject.CommonName
		if len(certChain[0].Subject.Organization) > 0 {
			result.CertificateOrganization = certChain[0].Subject.Organization[0]
		}
	}

	// Step 4: Verify envelopeManifestSignedContent and extract manifest
	manifest, err := verifyAndExtractManifest(
		input.Envelope.EnvelopeManifestSignedContent,
		input.PublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("BSIG: envelope manifest signature verification failed: %w", err)
	}
	result.Manifest = manifest

	// Step 5: Verify transport document JSON checksum
	transportDocChecksum, err := verifyTransportDocumentChecksum(
		input.Envelope.TransportDocument,
		manifest.TransportDocumentChecksum,
	)
	if err != nil {
		return nil, fmt.Errorf("BENV: transport document verification failed: %w", err)
	}
	result.TransportDocumentChecksum = transportDocChecksum

	// Step 6: Verify transfer chain and get last entry
	lastEntry, err := verifyEnvelopeTransferChain(
		input.Envelope.EnvelopeTransferChain,
		manifest,
		input.PublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("BENV: transfer chain verification failed: %w", err)
	}
	result.LastTransferChainEntry = lastEntry

	// Step 7: Verify transport document checksums match between manifest and last entry (anti-replay protection)
	if manifest.TransportDocumentChecksum != lastEntry.TransportDocumentChecksum {
		return result, fmt.Errorf("BENV: anti-replay check failed: transport document checksums don't match (manifest: %s, last entry: %s)",
			manifest.TransportDocumentChecksum, lastEntry.TransportDocumentChecksum)
	}

	// All checks passed
	return result, nil
}

// validateX5C validates the x5c certificate chain (if present) in the JWS headers.
//
// This performs consistency checks between x5c, JWKS public key, and expected domain.
//
// Parameters:
//   - jwsString: The JWS string
//   - publicKeyFromJWKS: The public key fetched from JWKS endpoint (looked up by JWS kid header)
//   - expectedDomain: The expected sender domain from DCSA registry
//   - rootCAs: Root CA pool for certificate validation (nil = use system roots)
//
// Returns:
//   - certChain: The validated certificate chain (nil if x5c not present)
//   - error: Any validation errors
func validateX5C(
	jwsString string,
	publicKeyFromJWKS any,
	expectedDomain string,
	rootCAs *x509.CertPool,
) ([]*x509.Certificate, error) {

	// Step 1: Extract x5c from JWS (if present)
	certChain, err := crypto.ParseX5CFromJWS(jwsString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x5c: %w", err)
	}

	// cert chain is optional in JWS so return early if not present
	if certChain == nil {
		return nil, nil
	}

	// Step 2: Validate x5c public key matches JWKS public key
	// prevents inclusion of a legitimate cert but signed wih different key
	if err := crypto.ValidateX5CMatchesKey(certChain, publicKeyFromJWKS); err != nil {
		return nil, fmt.Errorf("x5c public key does not match JWKS public key: %w", err)
	}

	// Step 3: Validate certificate chain (CA trust, expiry, domain)
	// prevents inclusion of an invalid cert chain
	if err := crypto.ValidateCertificateChain(certChain, rootCAs, expectedDomain); err != nil {
		return nil, fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return certChain, nil
}

// verifyAndExtractManifest verifies the envelopeManifestSignedContent JWS and extracts the EnvelopeManifest payload.
//
// the manifest contains the checksums used to verify the integrity of the transport document and the last transfer chain entry.
//
// The publicKey should come from a JWK endpoint or stored certificate (looked up by kid).
func verifyAndExtractManifest(
	manifestSignedContent crypto.EnvelopeManifestSignedContent,
	publicKey any,
) (*crypto.EnvelopeManifest, error) {

	// Verify JWS signature using public key from JWKS/stored cert
	payloadBytes, err := crypto.VerifyJWS(string(manifestSignedContent), publicKey)
	if err != nil {
		return nil, fmt.Errorf("JWS signature verification failed: %w", err)
	}

	// Parse the manifest payload
	var manifest crypto.EnvelopeManifest
	if err := json.Unmarshal(payloadBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest payload: %w", err)
	}

	// Validate manifest structure
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("manifest validation failed: %w", err)
	}

	return &manifest, nil
}

// verifyTransportDocumentChecksum verifies the transport document (eBL) JSON has not been tampered with.
func verifyTransportDocumentChecksum(
	transportDocument json.RawMessage,
	expectedChecksum string,
) (string, error) {

	// Canonicalize the transport document JSON
	canonicalJSON, err := crypto.CanonicalizeJSON(transportDocument)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize transport document: %w", err)
	}

	// Compute SHA-256 checksum
	actualChecksum, err := crypto.Hash(canonicalJSON)
	if err != nil {
		return "", fmt.Errorf("failed to compute transport document checksum: %w", err)
	}

	// Verify checksum matches
	if actualChecksum != expectedChecksum {
		return "", fmt.Errorf("transport document checksum mismatch: expected %s, got %s",
			expectedChecksum, actualChecksum)
	}

	return actualChecksum, nil
}

// verifyEnvelopeTransferChain verifies the transfer chain integrity and returns the last entry.
//
// This function:
//   - Verifies the last entry checksum matches the manifest
//   - Walks backwards through the entire chain verifying all cryptographic links
//   - Verifies all entry signatures
//   - Checks that the first entry has a valid issuanceManifestSignedContent
//   - Returns the verified last entry
func verifyEnvelopeTransferChain(
	envelopeTransferChain []crypto.EnvelopeTransferChainEntrySignedContent,
	manifest *crypto.EnvelopeManifest,
	publicKey any,
) (*crypto.EnvelopeTransferChainEntry, error) {

	if len(envelopeTransferChain) == 0 {
		return nil, fmt.Errorf("transfer chain is empty")
	}

	// Step 1: Verify last entry checksum matches the checksum in the manifest
	lastEntryJWS := envelopeTransferChain[len(envelopeTransferChain)-1]
	actualChecksum, err := crypto.Hash([]byte(lastEntryJWS))
	if err != nil {
		return nil, fmt.Errorf("failed to compute last entry checksum: %w", err)
	}

	if actualChecksum != manifest.LastEnvelopeTransferChainEntrySignedContentChecksum {
		return nil, fmt.Errorf("last transfer chain entry checksum mismatch: expected %s, got %s",
			manifest.LastEnvelopeTransferChainEntrySignedContentChecksum, actualChecksum)
	}

	// Step 2: verify the chain
	// Start from the last entry and work backwards, verify signatures and payload
	// verify the crypographic links between entries

	lastEntry := &crypto.EnvelopeTransferChainEntry{}

	for i := len(envelopeTransferChain) - 1; i >= 0; i-- {
		currentEntryJWS := envelopeTransferChain[i]

		// Verify current entry signature and extract payload
		currentPayloadBytes, err := crypto.VerifyJWS(string(currentEntryJWS), publicKey)
		if err != nil {
			return nil, fmt.Errorf("entry %d JWS signature verification failed: %w", i, err)
		}

		var currentEntry crypto.EnvelopeTransferChainEntry
		if err := json.Unmarshal(currentPayloadBytes, &currentEntry); err != nil {
			return nil, fmt.Errorf("failed to parse entry %d payload: %w", i, err)
		}

		// we need to return the last entry so we can verify the anti-replay protection
		if i == len(envelopeTransferChain)-1 {
			lastEntry = &currentEntry
		}

		// Validate the entry has all the mandatory fields
		if err := currentEntry.Validate(); err != nil {
			return nil, fmt.Errorf("entry %d validation failed: %w", i, err)
		}

		if i > 0 {
			// verify the link to the previous entry
			previousEntryJWS := envelopeTransferChain[i-1]

			// Compute checksum of previous entry
			previousChecksum, err := crypto.Hash([]byte(previousEntryJWS))
			if err != nil {
				return nil, fmt.Errorf("failed to compute checksum for entry %d: %w", i-1, err)
			}

			// current entry should reference previous entry's checksum
			if currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum == nil {
				return nil, fmt.Errorf("entry %d is missing previousEnvelopeTransferChainEntrySignedContentChecksum", i)
			}

			if *currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum != previousChecksum {
				return nil, fmt.Errorf("entry %d chain link broken: expected previous checksum %s, got %s",
					i, previousChecksum, *currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum)
			}
		}
	}

	return lastEntry, nil
}
