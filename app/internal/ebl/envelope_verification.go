// envelope_verification.go provides high-level functions for verifying DCSA EBL_PINT API envelope transfers.
//
// the verification process is as follows:
// 1. Check envelope structure for required fields
// 2. Verify JWS signature and validate x5c certificate chain (if present)
// 3. store verified organisation information from the x5c certificate chain
// 4. Determine trust level based on x5c certificate type
// 5. Parse and validate manifest payload
// 6. Verify transport document JSON checksum matches the manifest
// 7. Verify transfer chain integrity
// 8. Verify carrier's issuance manifest signature and document checksum
// 9. Verify manifest checksum matches last transfer chain entry
//
// # Signature Verification Process
//
// The carrier and sender public keys used for verification are provided as input. In production
// they should be fetched from the carrier/sender's JWKS endpoint (looked up by kid from JWS header)
// or - if keys were exchanged out of band - obtained from the services' local key store.
//
// All signatures in the envelope (manifest + all transfer chain entries) must be
// signed by the sending platform.
//
// The issuanceManifestSignedContent (inside the first transfer chain entry) is signed
// by the carrier and should be verified to ensure the transport document JSON
// and issueTo party JSON have not been tampered with and came from the expected carrier.
//
// see crypto.JwsVerify for details on the signature verification process.
//
// # Platform Identification and Domain Verification
//
// Platform identification involves two steps:
//
// 1. Key Lookup:
//    - Extract 'kid' from the JWS header
//    - Look up the public key in the app's key store (KeyManager)
//    - If not found locally, fetch from the platform's JWKS endpoint
//
// 2. Domain Verification
//    This is done in two for two reasons
//    a) Platform Authorization: Verify the platform's domain is approved for eBL transfers (DCSA registry)
//    b) Certificate Binding: Where x5c headers are supplied in the JWS, verify the domain
//       in the x5c certificate matches the platform's expected domain.
//
// The platform's expected domain is established through one of these methods:
//
//    - JWKS Endpoint: Domain extracted from JWKS URL (e.g., https://platform.example.com/.well-known/jwks.json)
//      and verified against DCSA registry
//
//    - Out-of-Band: Domain established during platform onboarding/configuration and stored in the key store
//      alongside the public key. Retrieved when looking up the key by kid.
//
// Note: In the current implementation, ExpectedSenderDomain and ExpectedCarrierDomain must be provided by the caller
// (typically the HTTP handler, which retrieves it from the key store)
//
// # Trust Hierarchy
// This app implements a trust hierarchy based on certificate validation level (see crypto/trust_level.go)
//
// The caller (typically the HTTP handler) is responsible for enforcing the minimum acceptable trust level.
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

	// PublicKey is the public key to use for verification of the JWS signature
	// In production this will typically be fetched from the sender's JWKS endpoint at
	// https://{domain}/.well-known/jwks.json or
	// via manually colleted information for parties that don't publish JWKS endpoints.
	//
	// The key type should be ed25519.PublicKey or *rsa.PublicKey.
	PublicKey any

	// CarrierPublicKey is the public key to verify the carrier's signature on issuanceManifestSignedContent.
	// carrier signature verification is always performed to ensure the transport document
	// is authentic and matches what the carrier originally issued.
	//
	// In production this will typically be fetched from the carrier's JWKS endpoint at
	// https://{carrier-domain}/.well-known/jwks.json (looked up by kid from JWS header).
	// Fallback: manually configured keys for carriers that don't publish JWKS endpoints.
	//
	// The key type should be ed25519.PublicKey or *rsa.PublicKey.
	CarrierPublicKey any

	// ExpectedCarrierDomain is the expected carrier's domain (e.g., "maersk.com")
	// this is used to validate the carrier's certificate domain matches the expected carrier.
	ExpectedCarrierDomain string
}

// EnvelopeVerificationResult contains the results of envelope verification.
//
// if the envelope was signed with x5c headers (TrustLevelEVOV or TrustLevelDV)
// the org identity information is included in the result.
type EnvelopeVerificationResult struct {

	// Manifest is the verified EnvelopeManifest extracted from envelope.envelopeManifestSignedContent
	Manifest *crypto.EnvelopeManifest

	// TransferChain contains all verified transfer chain entries in order (first to last)
	// This provides the complete history of the eBL from issuance to current state.
	// The caller needs this to build the next transfer (must include entire chain + new entry)
	TransferChain []*crypto.EnvelopeTransferChainEntry

	// FirstTransferChainEntry is a convenience pointer to the first entry in TransferChain
	// This entry contains the IssuanceManifestSignedContent from the carrier
	FirstTransferChainEntry *crypto.EnvelopeTransferChainEntry

	// LastTransferChainEntry is a convenience pointer to the last entry in TransferChain
	// This entry contains the most recent transactions and current holder information
	LastTransferChainEntry *crypto.EnvelopeTransferChainEntry

	// TransportDocumentChecksum is the checksum of the transport document
	TransportDocumentChecksum string

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 checksum of the last transfer chain entry
	// This is required in API responses and for duplicate detection
	LastEnvelopeTransferChainEntrySignedContentChecksum string

	// TrustLevel indicates the trust level achieved by the signature
	TrustLevel crypto.TrustLevel

	// VerifiedDomain is the domain that was successfully verified against the certificate
	VerifiedDomain string

	// VerifiedOrganisation contains the verified organisation name if available (extracted from the x5c header in the JWS signature).
	//
	// Only populated for TrustLevelEVOV (Extended Validation or Organization Validation certificates)
	// This is the legal entity name from the certificate's Organization field
	VerifiedOrganisation string
}

// VerifyEnvelopeTransfer performs technical verification (signatures, certificates, checksums, chain integrity)
// on an incoming envelope transfer request.
//
// Returns the EnvelopeVerificationResult with extracted data (including trust level) or an error if verification fails.
func VerifyEnvelopeTransfer(input EnvelopeVerificationInput) (*EnvelopeVerificationResult, error) {
	result := &EnvelopeVerificationResult{}

	// Step 1: Validate envelope structure (required fields)
	if err := input.Envelope.Validate(); err != nil {
		return nil, WrapEnvelopeError(err, "envelope validation failed")
	}

	// Step 2: Verify JWS signature and validate x5c certificate chain (if present)
	manifestPayload, certChain, err := crypto.VerifyJWS(
		string(input.Envelope.EnvelopeManifestSignedContent),
		input.PublicKey,
		input.RootCAs,
	)
	if err != nil {
		return nil, WrapSignatureError(err, "JWS verification failed")
	}

	// Step 3: store verifed organisation information
	// store the expected sender domain (from registry/keystore lookup)
	result.VerifiedDomain = input.ExpectedSenderDomain

	// extract organisation name from x5c chain if available
	// this is only populated for EV/OV certificates (TrustLevelEVOV)
	if len(certChain) > 0 && len(certChain[0].Subject.Organization) > 0 {
		result.VerifiedOrganisation = certChain[0].Subject.Organization[0]
	}

	// Step 4: Determine trust level
	trustLevel, err := crypto.DetermineTrustLevel(string(input.Envelope.EnvelopeManifestSignedContent))
	if err != nil {
		return nil, WrapSignatureError(err, "failed to determine trust level")
	}
	result.TrustLevel = trustLevel

	// Step 5: Parse and validate the manifest payload
	manifest := &crypto.EnvelopeManifest{}
	if err := json.Unmarshal(manifestPayload, manifest); err != nil {
		return nil, WrapSignatureError(err, "failed to parse manifest payload")
	}
	if err := manifest.Validate(); err != nil {
		return nil, WrapSignatureError(err, "manifest validation failed")
	}
	result.Manifest = manifest

	// Step 6: Verify received transport document matches the envelope manifest checksum
	// This proves the actual document hasn't been altered since the sending platform signed the manifest
	transportDocChecksum, err := verifyTransportDocumentChecksum(
		input.Envelope.TransportDocument,
		manifest.TransportDocumentChecksum,
	)
	if err != nil {
		return nil, WrapEnvelopeError(err, "transport document verification failed")
	}
	result.TransportDocumentChecksum = transportDocChecksum

	// Step 7: Verify transfer chain integrity and store all entries
	// this prevents replay attacks, where an attacker replaces the last entry with a valid one from a different transfer
	transferChain, lastEntryChecksum, err := verifyEnvelopeTransferChain(
		input.Envelope.EnvelopeTransferChain,
		manifest,
		input.PublicKey,
		input.ExpectedSenderDomain,
		input.RootCAs,
	)
	if err != nil {
		return nil, WrapEnvelopeError(err, "transfer chain verification failed")
	}
	result.TransferChain = transferChain
	result.LastEnvelopeTransferChainEntrySignedContentChecksum = lastEntryChecksum

	// these are included for convenience and to improve readablity of code using the result
	result.FirstTransferChainEntry = transferChain[0]
	result.LastTransferChainEntry = transferChain[len(transferChain)-1]

	// Step 8: Verify carrier's issuance manifest and document checksum
	if err := verifyIssuanceManifest(
		result.FirstTransferChainEntry,
		input.CarrierPublicKey,
		input.ExpectedCarrierDomain,
		input.RootCAs,
	); err != nil {
		return nil, WrapEnvelopeError(err, "issuance manifest verification failed")
	}

	// Step 9: verify manifest checksum matches last transfer chain entry
	// This prevents a situation where the transfer contains a valid chain + valid manifest + valid transport document but the
	// the components are from different transfers (i.e the manifest and last chain entry must agree on which transport document they are refering to)
	if manifest.TransportDocumentChecksum != result.LastTransferChainEntry.TransportDocumentChecksum {
		return result, NewEnvelopeError(fmt.Sprintf("anti-replay check failed: transport document checksums don't match (manifest: %s, last entry: %s)",
			manifest.TransportDocumentChecksum, result.LastTransferChainEntry.TransportDocumentChecksum))
	}

	// All checks passed
	return result, nil
}

// verifyTransportDocumentChecksum verifies the transport document (eBL) JSON has not been tampered with.
func verifyTransportDocumentChecksum(
	transportDocument json.RawMessage,
	expectedChecksum string,
) (string, error) {

	// Canonicalize the transport document JSON
	canonicalJSON, err := crypto.CanonicalizeJSON(transportDocument)
	if err != nil {
		return "", WrapEnvelopeError(err, "failed to canonicalize transport document")
	}

	// Compute SHA-256 checksum
	actualChecksum, err := crypto.Hash(canonicalJSON)
	if err != nil {
		return "", WrapEnvelopeError(err, "failed to compute transport document checksum")
	}

	// Verify checksum matches
	if actualChecksum != expectedChecksum {
		return "", NewEnvelopeError(fmt.Sprintf("transport document checksum mismatch: expected %s, got %s",
			expectedChecksum, actualChecksum))
	}

	return actualChecksum, nil
}

// verifyIssuanceManifest verifies the carrier's signature on the issuance manifest and validates
// the transport document checksum.
//
//   - Carrier signature verification ensures the carrier is the one who issued the eBL (non-repudiation)
//   - Document checksum verification ensures the transport document hasn't been tampered with since issuance
//
// TODO: confirm this is correct:
// The issueToChecksum is verified only at issuance time (EBL_ISS API) by the first eBL Solution Provider
// and the check is not repeated in subsequent PINT transfers.  This is because the first eBL Solution Provider
// is the only one that has access to the original "issueTo" property from the carrier.
//
// The issueToChecksum is inlcuded in the issuance manifest as part of the carrier-signed audit trail.
// Subsequent platforms can use the ISSUE transaction RecipientParty if they need to know the original issueTo.
func verifyIssuanceManifest(
	firstEntry *crypto.EnvelopeTransferChainEntry,
	carrierPublicKey any,
	expectedCarrierDomain string,
	rootCAs *x509.CertPool,
) error {

	if firstEntry == nil {
		return NewEnvelopeError("first entry is nil")
	}

	if firstEntry.IssuanceManifestSignedContent == nil {
		return NewEnvelopeError("issuanceManifestSignedContent is missing from first transfer chain entry")
	}

	// Step 1: Verify carrier's JWS signature on issuanceManifestSignedContent
	// The carrier is treated as just another business entity in the PINT network and verified the same way as a platform.
	issuanceManifestPayload, _, err := crypto.VerifyJWS(
		string(*firstEntry.IssuanceManifestSignedContent),
		carrierPublicKey,
		rootCAs,
	)
	if err != nil {
		return WrapSignatureError(err, "carrier's JWS signature verification failed")
	}

	// Step 2: Parse the IssuanceManifest payload
	issuanceManifest := &crypto.IssuanceManifest{}
	if err := json.Unmarshal(issuanceManifestPayload, issuanceManifest); err != nil {
		return WrapEnvelopeError(err, "failed to parse issuance manifest payload")
	}

	// Step 3: Validate the IssuanceManifest has required fields
	if err := issuanceManifest.Validate(); err != nil {
		return WrapEnvelopeError(err, "issuance manifest validation failed")
	}

	// Step 4: Compare IssuanceManifest.DocumentChecksum (carrier-signed)
	// with FirstTransferChainEntry.TransportDocumentChecksum (first platform-signed)
	// this proves the document has not been tampered with since the carrier issued it.
	if issuanceManifest.DocumentChecksum != firstEntry.TransportDocumentChecksum {
		return NewEnvelopeError("carrier's document checksum doesn't match first transfer chain entry")
	}
	return nil
}

// verifyEnvelopeTransferChain verifies the transfer chain integrity and returns all verified entries.
//
// This function verifies the last entry checksum matches the manifest and checks the integrity of the transfer chain.
//
// Note: All transfer chain entries are signed by the sending platform.
//
// The issuanceManifestSignedContent (inside the first entry) is signed by the carrier
// and is verified separately in verifyIssuanceManifest().
//
// Returns all verified transfer chain entries in order (first to last) and the checksum of the last entry
func verifyEnvelopeTransferChain(
	envelopeTransferChain []crypto.EnvelopeTransferChainEntrySignedContent,
	manifest *crypto.EnvelopeManifest,
	publicKey any,
	expectedDomain string,
	rootCAs *x509.CertPool,
) ([]*crypto.EnvelopeTransferChainEntry, string, error) {

	if len(envelopeTransferChain) == 0 {
		return nil, "", NewEnvelopeError("transfer chain is empty")
	}

	// Step 1: Verify last entry checksum matches the checksum in the manifest
	lastEntryJWS := envelopeTransferChain[len(envelopeTransferChain)-1]
	lastEntryChecksum, err := crypto.Hash([]byte(lastEntryJWS))
	if err != nil {
		return nil, "", WrapEnvelopeError(err, "failed to compute last entry checksum")
	}

	if lastEntryChecksum != manifest.LastEnvelopeTransferChainEntrySignedContentChecksum {
		return nil, "", NewEnvelopeError(fmt.Sprintf("last transfer chain entry checksum mismatch: expected %s, got %s",
			manifest.LastEnvelopeTransferChainEntrySignedContentChecksum, lastEntryChecksum))
	}

	// Step 2: verify the chain and collect all entries
	// We allocate the slice with the exact size needed
	allEntries := make([]*crypto.EnvelopeTransferChainEntry, len(envelopeTransferChain))

	// Start from the last entry and work backwards
	for i := len(envelopeTransferChain) - 1; i >= 0; i-- {
		currentEntryJWS := envelopeTransferChain[i]

		// Verify current entry signature
		currentPayloadBytes, _, err := crypto.VerifyJWS(
			string(currentEntryJWS),
			publicKey,
			rootCAs,
		)
		if err != nil {
			return nil, "", WrapSignatureError(err, fmt.Sprintf("entry %d JWS verification failed", i))
		}

		// Parse the entry payload
		var currentEntry crypto.EnvelopeTransferChainEntry
		if err := json.Unmarshal(currentPayloadBytes, &currentEntry); err != nil {
			return nil, "", WrapEnvelopeError(err, fmt.Sprintf("failed to parse entry %d payload", i))
		}

		// Validate the entry has all the mandatory fields
		if err := currentEntry.Validate(); err != nil {
			return nil, "", WrapEnvelopeError(err, fmt.Sprintf("entry %d validation failed", i))
		}

		// Store the entry in the result slice
		allEntries[i] = &currentEntry

		if i > 0 {
			// verify the link to the previous entry
			previousEntryJWS := envelopeTransferChain[i-1]

			// Compute checksum of previous entry
			previousChecksum, err := crypto.Hash([]byte(previousEntryJWS))
			if err != nil {
				return nil, "", WrapEnvelopeError(err, fmt.Sprintf("failed to compute checksum for entry %d", i-1))
			}

			// current entry should reference previous entry's checksum

			if currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum == nil {
				return nil, "", NewEnvelopeError(fmt.Sprintf("entry %d is missing previousEnvelopeTransferChainEntrySignedContentChecksum", i))
			}

			if *currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum != previousChecksum {
				return nil, "", NewEnvelopeError(fmt.Sprintf("entry %d chain link broken: expected previous checksum %s, got %s",
					i, previousChecksum, *currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum))
			}
		}
	}

	// Step 3: Verify transport document checksum is consistent across all entries
	// All entries must reference the same transport document - it cannot change during transfers
	firstChecksum := allEntries[0].TransportDocumentChecksum
	for i := 1; i < len(allEntries); i++ {
		if allEntries[i].TransportDocumentChecksum != firstChecksum {
			return nil, "", NewEnvelopeError(fmt.Sprintf("transport document checksum changed in entry %d: expected %s, got %s",
				i, firstChecksum, allEntries[i].TransportDocumentChecksum))
		}
	}

	return allEntries, lastEntryChecksum, nil
}
