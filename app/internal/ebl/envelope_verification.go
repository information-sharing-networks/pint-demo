package ebl

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
// # Platform Identification
//
// Platform identification is done by looking up the platform in the DCSA registry
// using the JWS key ID (see app/internal/pint/keymanager.go)
//
// # Key ID (kid) Usage
// This app uses the JWK thumbprint of the signing public key as the key ID.
//
// # Trust Hierarchy
// This app implements a trust hierarchy based on the type of certificate in the
// x5c header (if present) - see crypto/trust_level.go
//
// The caller (typically the HTTP handler) is responsible for enforcing the minimum acceptable trust level.

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// EnvelopeVerificationInput contains the data needed to verify an envelope transfer.
type EnvelopeVerificationInput struct {

	// Envelope is the complete eBL Envelope received from POST /v3/envelopes
	Envelope *EblEnvelope

	// RootCAs is the root CA pool for certificate validation
	// nil = use system roots (typically used for production), custom pool = testing/private CA
	RootCAs *x509.CertPool

	// KeyProvider is used to fetch public keys for JWS signature verification.
	//
	// In production, this should be a KeyManager instance that fetches keys from:
	// - JWKS endpoints (e.g., https://{domain}/.well-known/jwks.json)
	// - Manually configured keys for parties that don't publish JWKS endpoints
	//
	// The KeyProvider must be able to provide keys for the sending platform
	// that was used to sign envelopeManifestSignedContent and transfer chain entries.
	KeyProvider jws.KeyProvider
}

// EnvelopeVerificationResult contains the results of envelope verification.
//
// if the envelope was signed with x5c headers (TrustLevelEVOV or TrustLevelDV)
// the org identity information is included in the result.
type EnvelopeVerificationResult struct {

	// Manifest is the verified EnvelopeManifest extracted from envelope.envelopeManifestSignedContent
	Manifest *EnvelopeManifest

	// TransferChain contains all verified transfer chain entries in order (first to last)
	// This provides the complete history of the eBL from issuance to current state.
	// The caller needs this to build the next transfer (must include entire chain + new entry)
	TransferChain []*EnvelopeTransferChainEntry

	// FirstTransferChainEntry is a convenience pointer to the first entry in TransferChain
	// This entry contains the IssuanceManifestSignedContent from the carrier
	FirstTransferChainEntry *EnvelopeTransferChainEntry

	// LastTransferChainEntry is a convenience pointer to the last entry in TransferChain
	// This entry contains the most recent transactions and current holder information
	LastTransferChainEntry *EnvelopeTransferChainEntry

	// TransportDocumentChecksum is the checksum of the transport document
	TransportDocumentChecksum string

	// TransportDocumentReference is the unique number allocated by the shipping line to the transport document.
	// This is a required field per DCSA spec (max 20 chars) and is extracted during verification.
	// Used for tracking the shipment status and database storage.
	TransportDocumentReference string

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 checksum of the last transfer chain entry
	// This is required in API responses and for duplicate detection
	LastEnvelopeTransferChainEntrySignedContentChecksum string

	// TrustLevel indicates the trust level achieved by the signature
	TrustLevel crypto.TrustLevel

	// VerifiedDomain is the domain that was extracted from the x5c certificate chain (if present)
	VerifiedDomain string

	// VerifiedOrganisation contains the verified organisation name extracted from the x5c certificate chain (if present)
	//
	// Only populated for TrustLevelEVOV (Extended Validation or Organization Validation certificates)
	// This is the legal entity name from the certificate's Organization field
	VerifiedOrganisation string
}

// VerifyEnvelopeTransfer performs technical verification (signatures, certificates, checksums, chain integrity)
// on an incoming envelope transfer request.
//
// Typically you will supply the server's KeyManager as the KeyProvider (it will be used
// to automatically fetch the public keys needed to verify the signatures, based on the JWS kid)
//
// Returns the EnvelopeVerificationResult with extracted data (including trust level) or an error if verification fails.
func VerifyEnvelopeTransfer(input EnvelopeVerificationInput) (*EnvelopeVerificationResult, error) {
	result := &EnvelopeVerificationResult{}

	// Step 1: Validate envelope structure (required fields)
	if err := input.Envelope.Validate(); err != nil {
		return nil, WrapEnvelopeError(err, "envelope validation failed")
	}

	// Step 2: Verify JWS signature and validate x5c certificate chain (if present)
	manifestPayload, _, certChain, err := crypto.VerifyJWSWithKeyProvider(
		string(input.Envelope.EnvelopeManifestSignedContent),
		input.KeyProvider,
		input.RootCAs,
	)
	if err != nil {
		return nil, WrapSignatureError(err, "JWS verification failed")
	}

	// Step 3: extract the domain from the leaf (platform) certificate if the x5c header was present
	if len(certChain) > 0 {
		// try the sans first and fall back to the common name if not available
		// note CN is not verified and might not be a valid domain
		if len(certChain[0].DNSNames) > 0 {
			result.VerifiedDomain = certChain[0].DNSNames[0]
		} else {
			result.VerifiedDomain = certChain[0].Subject.CommonName
		}
	}

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
	manifest := &EnvelopeManifest{}
	if err := json.Unmarshal(manifestPayload, manifest); err != nil {
		return nil, WrapSignatureError(err, "failed to parse manifest payload")
	}
	if err := manifest.Validate(); err != nil {
		return nil, WrapSignatureError(err, "manifest validation failed")
	}
	result.Manifest = manifest

	// Step 6: Verify received transport document matches the envelope manifest checksum
	// This proves the actual document hasn't been altered since the sending platform signed the manifest
	// Also extracts the required transportDocumentReference field
	transportDocumentResult, err := verifyTransportDocumentChecksum(
		input.Envelope.TransportDocument,
		manifest.TransportDocumentChecksum,
	)
	if err != nil {
		return nil, WrapEnvelopeError(err, "transport document verification failed")
	}
	result.TransportDocumentChecksum = manifest.TransportDocumentChecksum
	result.TransportDocumentReference = transportDocumentResult.TransportDocumentReference

	// Step 7: Verify transfer chain integrity and store all entries
	// this prevents replay attacks, where an attacker replaces the last entry with a valid one from a different transfer
	transferChain, lastEntryChecksum, err := verifyEnvelopeTransferChain(
		input.Envelope.EnvelopeTransferChain,
		manifest,
		input.KeyProvider,
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
		input.KeyProvider,
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

type TransportDocumentResult struct {
	// TransportDocumentReference is the unique number allocated by the shipping line to the transport document.
	// This is a required field and used for tracking the shipment status and database storage.
	TransportDocumentReference string
}

// verifyTransportDocumentChecksum verifies the transport document (eBL) JSON has not been tampered with
// and extracts the required transportDocumentReference field.
//
// Returns an error if the calculated checksum does not match the expected value
// or if the transportDocumentReference is missing.
func verifyTransportDocumentChecksum(
	transportDocument json.RawMessage,
	expectedChecksum string,
) (*TransportDocumentResult, error) {

	// Canonicalize the transport document JSON
	canonicalJSON, err := crypto.CanonicalizeJSON(transportDocument)
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to canonicalize transport document")
	}

	// Compute SHA-256 checksum
	actualChecksum, err := crypto.Hash(canonicalJSON)
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to compute transport document checksum")
	}

	// Verify checksum matches
	if actualChecksum != expectedChecksum {
		return nil, NewEnvelopeError(fmt.Sprintf("transport document checksum mismatch: expected %s, got %s",
			expectedChecksum, actualChecksum))
	}

	// Parse the transport document to extract required fields
	var transportDoc map[string]any
	if err := json.Unmarshal(transportDocument, &transportDoc); err != nil {
		return nil, WrapEnvelopeError(err, "failed to parse transport document JSON")
	}

	// Extract transportDocumentReference (required field per DCSA spec)
	TransportDocumentResult := &TransportDocumentResult{}

	// Use type assertion with ok pattern to safely check if field exists and is a string
	ref, ok := transportDoc["transportDocumentReference"].(string)
	if !ok || ref == "" {
		return nil, NewEnvelopeError("transportDocumentReference is required in transport document")
	}
	TransportDocumentResult.TransportDocumentReference = ref

	return TransportDocumentResult, nil
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
	firstEntry *EnvelopeTransferChainEntry,
	keyProvider jws.KeyProvider,
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
	// The KeyProvider will extract the carrier's KID from the JWS header and fetch the appropriate key.
	issuanceManifestPayload, _, _, err := crypto.VerifyJWSWithKeyProvider(
		string(*firstEntry.IssuanceManifestSignedContent),
		keyProvider,
		rootCAs,
	)
	if err != nil {
		return WrapSignatureError(err, "carrier's JWS signature verification failed")
	}

	// Step 2: Parse the IssuanceManifest payload
	issuanceManifest := &IssuanceManifest{}
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
	envelopeTransferChain []EnvelopeTransferChainEntrySignedContent,
	manifest *EnvelopeManifest,
	keyProvider jws.KeyProvider,
	rootCAs *x509.CertPool,
) ([]*EnvelopeTransferChainEntry, string, error) {

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
	allEntries := make([]*EnvelopeTransferChainEntry, len(envelopeTransferChain))

	// Start from the last entry and work backwards
	for i := len(envelopeTransferChain) - 1; i >= 0; i-- {
		currentEntryJWS := envelopeTransferChain[i]

		// Verify current entry signature using KeyProvider
		// The KeyProvider will extract the KID from each entry's JWS header and fetch the appropriate key
		currentPayloadBytes, _, _, err := crypto.VerifyJWSWithKeyProvider(
			string(currentEntryJWS),
			keyProvider,
			rootCAs,
		)
		if err != nil {
			return nil, "", WrapSignatureError(err, fmt.Sprintf("entry %d JWS verification failed", i))
		}

		// Parse the entry payload
		var currentEntry EnvelopeTransferChainEntry
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
