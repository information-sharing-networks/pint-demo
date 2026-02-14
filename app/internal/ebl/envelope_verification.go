package ebl

// envelope_verification.go provides high-level functions for verifying DCSA EBL_PINT API envelope transfers.
//
// # Signature Verification Process
//
// Each envelope includes the following signatures:
//
//	- The issuanceManifestSignedContent (inside the first transfer chain entry) is signed by the carrier.
// 	- Each transfer chain entry is signed by the platform that created it (identified by the eblPlatform field).
//	- The envelope manifest is also signed by the platform that created the last transfer chain entry.
//
// The signature verification logic prevents:
//  - the sending platform tampering with a transfer chain entry created by another platform
//    (since they don't have the private key to re-sign it)
//  - substituting a transfer chain from another eBL
//    (since the manifest and last transfer chain entry checksums must match)
//  - tampering with the transfer chain by reordering, omitting or substituting entries
//    (since the hash chain linking entries would be invalidated)
//  - the sending platform posting an envelope to the wrong platform
//    (since the recipient platform in the last transfer chain entry must match the current platform)
//  - platforms signing a transfer chain entry claiming to be from another platform
//    (since the eblPlatform in each entry must match the platform that owns the signing key)
//	- a non-approved platform creating a transfer chain entry
//    (since the key ID in the signature must belong to a platform in the platform registry).
//
// Note: This verification cannot detect "double-spend" transfers (where a platform creates
// multiple valid but conflicting transfer chains). External validation via a Control
// Tracking Registry (CTR) is required to detect this.
//
// TODO: Some level of DISE (dispute) detection is possible by comparing the transfer
// chain history from multiple transfers of the same eBL to detect forks (conflicting
// histories). This is not yet implemented.
//
// # Platform Identification
//
// Platform identification is done by looking up the platform in the DCSA registry
// using the JWS key ID.
//
// In production the keystore is populated with public keys retrieved either from the
// platform's JWKS endpoint or from a local key store, depending on how the platform was
// configured in the platform registry.
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
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// KeyProviderWithLookup extends jws.KeyProvider with platform lookup capability.
//
// This interface is implemented by the KeyManager and allows envelope verification
// to both fetch keys for signature verification and validate that keys belong to
// the claimed platform.
type KeyProviderWithLookup interface {
	jws.KeyProvider
	LookupPlatformByKeyID(ctx context.Context, keyID string) (string, error)
}

// EnvelopeState is used to ensure that transfer chain actionCodes are sequenced correctly.
type EnvelopeState string

const (
	EnvelopeStateUnset                 EnvelopeState = ""
	EnvelopeStateIssue                 EnvelopeState = "ISSUE"
	EnvelopeStateTransfer              EnvelopeState = "TRANSFER"
	EnvelopeStateEndorse               EnvelopeState = "ENDORSE"
	EnvelopeStateEndorseToOrder        EnvelopeState = "ENDORSE_TO_ORDER"
	EnvelopeStateBlankEndorse          EnvelopeState = "BLANK_ENDORSE"
	EnvelopeStateSign                  EnvelopeState = "SIGN"
	EnvelopeStateSurrenderForAmendment EnvelopeState = "SURRENDER_FOR_AMENDMENT"
	EnvelopeStateSurrenderForDelivery  EnvelopeState = "SURRENDER_FOR_DELIVERY"
	EnvelopeStateSACC                  EnvelopeState = "SACC" // used by the carrier to accept a surrender request.
	EnvelopeStateSREJ                  EnvelopeState = "SREJ" // used by the carrier to reject a surrender request.
)

var validEnvelopeStateTransitions = map[EnvelopeState][]EnvelopeState{
	EnvelopeStateIssue:                 {EnvelopeStateTransfer, EnvelopeStateEndorse},
	EnvelopeStateTransfer:              {EnvelopeStateTransfer, EnvelopeStateEndorse, EnvelopeStateEndorseToOrder, EnvelopeStateBlankEndorse, EnvelopeStateSign, EnvelopeStateSurrenderForAmendment, EnvelopeStateSurrenderForDelivery},
	EnvelopeStateEndorse:               {EnvelopeStateTransfer, EnvelopeStateEndorse, EnvelopeStateEndorseToOrder, EnvelopeStateBlankEndorse, EnvelopeStateSign, EnvelopeStateSurrenderForAmendment, EnvelopeStateSurrenderForDelivery},
	EnvelopeStateSurrenderForAmendment: {EnvelopeStateSACC, EnvelopeStateSREJ},
	EnvelopeStateSurrenderForDelivery:  {EnvelopeStateSACC, EnvelopeStateSREJ},
	EnvelopeStateSACC:                  {}, // terminal state
	EnvelopeStateSREJ:                  {}, // terminal state
}

// isValidEnvelopeStateTransition checks if a transition from currentState to nextState is valid
// according to the DCSA specification.
//
// Returns true if the transition is allowed, false otherwise.
func isValidEnvelopeStateTransition(currentState, nextState EnvelopeState) bool {
	validTransitions, ok := validEnvelopeStateTransitions[currentState]
	if !ok {
		return false
	}
	return slices.Contains(validTransitions, nextState)
}

// EnvelopeVerificationInput contains the data needed to verify an envelope transfer.
type EnvelopeVerificationInput struct {

	// Envelope is the complete eBL Envelope received from POST /v3/envelopes
	Envelope *EblEnvelope

	// RootCAs is the root CA pool for certificate validation
	// nil = use system roots (typically used for production), custom pool = testing/private CA
	RootCAs *x509.CertPool

	// KeyProvider is used to fetch the public keys needed to verify the signatures in the envelope
	// and to lookup which platform owns a given key ID.
	//
	// In production, this should be the server's KeyManager instance.
	//
	// Depending on how the sending platform was
	// configured in the platform registry, the Keymanager fetches keys from either:
	//	- a JWKS endpoint (e.g., https://{domain}/.well-known/jwks.json)
	//	- a manually configured key (for platforms that don't publish JWKS endpoints).
	//
	// If the KeyProvider can't find the signature that the sending platform used to sign the
	// envelope manifest/last transfer chain entry, validation of the envelope fails.
	KeyProvider KeyProviderWithLookup

	// recipientPlatformCode is the platform code of the current platform.
	// This is used to verify the envelope transfer is addressed to the correct platform.
	RecipientPlatformCode string
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

	// RecipientPlatform is the intended recipient platform code extracted from the last transaction.
	// This is the DCSA platform code (e.g., "WAVE", "CARX", "EBL1") that identifies
	// which platform should receive this transfer.
	//
	// The handler should verify this matches the server's configured platform code.
	RecipientPlatform string

	// SenderPlatform is the platform code of the sender (from the last transfer chain entry's eblPlatform field).
	// This is provided for informational purposes and logging.
	SenderPlatform string

	// SenderKeyID is the key ID (kid) from the key used to sign the envelope manifest.
	// This identifies which key was used to sign the transfer and can be used to verify
	// the sender platform owns the signing key (via the key manager's public key lookup).
	SenderKeyID string
}

// VerifyEnvelope performs technical verification (signatures, certificates, checksums, chain integrity)
// on an incoming envelope transfer request.
//
// Returns;
//   - Successful validation returns a complete EnvelopeVerificationResult, including the trust level and org information, and nil error.
//   - Internal errors return ebl.InternalError and a nil EnvelopeVerificationResult
//   - Other errors are returned as either ebl.EnvelopeError or ebl.SignatureError with a non-nil EnvelopeVerificationResult containing partial information.
//     (minimally the LastEnvelopeTransferChainEntrySignedContentChecksum is returned to allow the caller to implement duplicate detection)
func VerifyEnvelope(input EnvelopeVerificationInput) (*EnvelopeVerificationResult, error) {
	result := &EnvelopeVerificationResult{}

	// Step 0: get the last transfer chain entry from the transfer chain - this is the unique identifier for the transfer
	// (the transfer chain is an array of JWS tokens - one for each transfer of the eBL)
	if len(input.Envelope.EnvelopeTransferChain) == 0 {
		return nil, NewEnvelopeError("envelope transfer chain is empty")
	}
	lastEntryJWS := input.Envelope.EnvelopeTransferChain[len(input.Envelope.EnvelopeTransferChain)-1]
	lastEntryChecksum, err := crypto.Hash([]byte(lastEntryJWS))
	if err != nil {
		return nil, WrapInternalError(err, "failed to retrieve last entry checksum")
	}

	// always return a result struct from this point - the only required field is the last entry checksum.
	// If verification fails later, the result struct will contain additional information about the failure
	result.LastEnvelopeTransferChainEntrySignedContentChecksum = lastEntryChecksum

	// Step 1: Validate envelope structure (required fields)
	if err := input.Envelope.ValidateStructure(); err != nil {
		return result, WrapEnvelopeError(err, "envelope validation failed")
	}

	// Step 2: Verify JWS signature and validate x5c certificate chain (if present)
	manifestPayload, _, certChain, err := crypto.VerifyJWSWithKeyProvider(
		string(input.Envelope.EnvelopeManifestSignedContent),
		input.KeyProvider,
		input.RootCAs,
	)
	if err != nil {
		return result, WrapSignatureError(err, "JWS verification failed")
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
		return result, WrapSignatureError(err, "failed to determine trust level")
	}
	result.TrustLevel = trustLevel

	// Step 5: Parse and validate the manifest payload
	manifest := &EnvelopeManifest{}
	if err := json.Unmarshal(manifestPayload, manifest); err != nil {
		return result, WrapEnvelopeError(err, "failed to parse manifest payload")
	}
	if err := manifest.ValidateStructure(); err != nil {
		return result, WrapEnvelopeError(err, "manifest validation failed")
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
		return result, WrapEnvelopeError(err, "transport document verification failed")
	}
	result.TransportDocumentChecksum = manifest.TransportDocumentChecksum
	result.TransportDocumentReference = transportDocumentResult.TransportDocumentReference

	// Step 7: Verify transfer chain integrity and store all entries
	// this prevents replay attacks, where an attacker replaces the last entry with a valid one from a different transfer
	transferChain, err := verifyEnvelopeTransferChain(
		input.Envelope.EnvelopeTransferChain,
		manifest,
		input.KeyProvider,
		input.RootCAs,
	)
	if err != nil {
		return result, WrapEnvelopeError(err, "transfer chain verification failed")
	}
	result.TransferChain = transferChain

	// these are included for convenience and to improve readablity of code using the result
	result.FirstTransferChainEntry = transferChain[0]
	result.LastTransferChainEntry = transferChain[len(transferChain)-1]

	// Step 8: Verify carrier's issuance manifest and document checksum
	if err := verifyIssuanceManifest(
		result.FirstTransferChainEntry,
		input.KeyProvider,
		input.RootCAs,
	); err != nil {
		return result, WrapEnvelopeError(err, "issuance manifest verification failed")
	}

	// Step 9: verify manifest checksum matches last transfer chain entry
	// This prevents a situation where the transfer contains a valid chain + valid manifest + valid transport document but the
	// the components are from different transfers (i.e the manifest and last chain entry must agree on which transport document they are refering to)
	if manifest.TransportDocumentChecksum != result.LastTransferChainEntry.TransportDocumentChecksum {
		return result, NewEnvelopeError(fmt.Sprintf("anti-replay check failed: transport document checksums don't match (manifest: %s, last entry: %s)",
			manifest.TransportDocumentChecksum, result.LastTransferChainEntry.TransportDocumentChecksum))
	}

	// Step 10: Extract and validate recipient platform from last transaction
	// (the recipient in the latest transaction identifies the intended receiving platform)
	lastEntry := result.LastTransferChainEntry
	if len(lastEntry.Transactions) == 0 {
		return result, NewEnvelopeError("last transfer chain entry must have at least one transaction")
	}

	lastTransaction := lastEntry.Transactions[len(lastEntry.Transactions)-1]
	if lastTransaction.Recipient == nil {
		return result, NewEnvelopeError("recipient is required in last transaction")
	}

	recipientPlatform := lastTransaction.Recipient.EblPlatform
	if recipientPlatform == "" {
		return result, NewEnvelopeError("recipient.eblPlatform is required")
	}

	// Extract sender platform from last entry
	senderPlatform := lastEntry.EblPlatform
	if senderPlatform == "" {
		return result, NewEnvelopeError("eblPlatform is required in last transfer chain entry")
	}

	// Extract the key ID (kid) from the envelope manifest signature header
	manifestHeader, err := crypto.ParseJWSHeader(string(input.Envelope.EnvelopeManifestSignedContent))
	if err != nil {
		return result, WrapSignatureError(err, "failed to parse manifest header")
	}

	// Extract the key ID (kid) from the last transfer chain entry signature header
	lastEntryHeader, err := crypto.ParseJWSHeader(string(input.Envelope.EnvelopeTransferChain[len(input.Envelope.EnvelopeTransferChain)-1]))
	if err != nil {
		return result, WrapSignatureError(err, "failed to parse last transfer chain entry header")
	}

	// Step 11: Verify that the manifest and last transfer chain entry were signed by the same key.
	// This prevents the sender substituting a different transfer chain signed by another platform.
	if manifestHeader.KeyID != lastEntryHeader.KeyID {
		return result, NewEnvelopeError(fmt.Sprintf(
			"envelope manifest and last transfer chain entry must be signed by the same key: "+
				"manifest kid=%s, last entry kid=%s",
			manifestHeader.KeyID, lastEntryHeader.KeyID))
	}

	result.RecipientPlatform = recipientPlatform
	result.SenderPlatform = senderPlatform
	result.SenderKeyID = manifestHeader.KeyID

	// Step 12: Verify the receiving platform in the envelope is the current platform
	// This prevents a platform from accepting an envelope that was not addressed to it
	if result.RecipientPlatform != input.RecipientPlatformCode {
		return result, NewEnvelopeError(fmt.Sprintf(
			"the envelope is addressed to platform %s but this platform is %s",
			result.RecipientPlatform, input.RecipientPlatformCode))
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

	// Extract kid for logging
	issuanceHeader, err := crypto.ParseJWSHeader(string(*firstEntry.IssuanceManifestSignedContent))
	if err == nil {
		slog.Debug("verifying issuance manifest signature", slog.String("kid", issuanceHeader.KeyID))
	}

	issuanceManifestPayload, _, _, err := crypto.VerifyJWSWithKeyProvider(
		string(*firstEntry.IssuanceManifestSignedContent),
		keyProvider,
		rootCAs,
	)
	if err != nil {
		return WrapSignatureError(err, "carrier's JWS signature verification failed")
	}
	slog.Debug("issuance manifest signature verified successfully")

	// Step 2: Parse the IssuanceManifest payload
	issuanceManifest := &IssuanceManifest{}
	if err := json.Unmarshal(issuanceManifestPayload, issuanceManifest); err != nil {
		return WrapEnvelopeError(err, "failed to parse issuance manifest payload")
	}

	// Step 3: Validate the IssuanceManifest has required fields
	if err := issuanceManifest.ValidateStructure(); err != nil {
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

// verifyEnvelopeTransferChain verifies transfer chain entry signatures and checksums and ensures that the transaction sequence is valid.
//
// The issuanceManifestSignedContent (inside the first entry) is signed by the carrier
// and is verified separately in verifyIssuanceManifest().
//
// **Note** this function cannot detect double spends (where the same eBL is sent twice with different transfer chains)
// this will need a CTR lookup to detect or for the platforms to share a common database.
//
// Returns all verified and decoded transfer chain entries in order (first to last)
func verifyEnvelopeTransferChain(
	envelopeTransferChain []EnvelopeTransferChainEntrySignedContent,
	manifest *EnvelopeManifest,
	keyProvider jws.KeyProvider,
	rootCAs *x509.CertPool,
) ([]*EnvelopeTransferChainEntry, error) {

	if len(envelopeTransferChain) == 0 {
		return nil, NewEnvelopeError("transfer chain is empty")
	}

	// Step 1: Verify last entry checksum matches the checksum in the manifest
	// this prevents an attacker from replacing the last entry with a valid one from a different transfer.
	lastEntryJWS := envelopeTransferChain[len(envelopeTransferChain)-1]
	lastEntryChecksum, err := crypto.Hash([]byte(lastEntryJWS))
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to compute last entry checksum")
	}

	if lastEntryChecksum != manifest.LastEnvelopeTransferChainEntrySignedContentChecksum {
		return nil, NewEnvelopeError(fmt.Sprintf("the last transfer chain entry checksum does not match the manifest: expected %s, got %s",
			manifest.LastEnvelopeTransferChainEntrySignedContentChecksum, lastEntryChecksum))
	}

	// Step 2: The first [`EnvelopeTransferChainEntry`](#/EnvelopeTransferChainEntry) in the `envelopeTransferChain[]` list should contain the `ISSUE` (issuance) transaction as the first transaction in the [`EnvelopeTransferChainEntry.transactions[]`](#/EnvelopeTransferChainEntry) list.
	firstEntryJWS := envelopeTransferChain[0]

	firstEntryPayloadBytes, _, _, err := crypto.VerifyJWSWithKeyProvider(
		string(firstEntryJWS),
		keyProvider,
		rootCAs,
	)
	if err != nil {
		return nil, WrapSignatureError(err, "first entry JWS verification failed")
	}

	// Step 3: Check the first entry contains an ISSUE transaction
	var firstEntry EnvelopeTransferChainEntry
	if err := json.Unmarshal(firstEntryPayloadBytes, &firstEntry); err != nil {
		return nil, WrapEnvelopeError(err, "failed to parse first entry payload")
	}
	if firstEntry.Transactions[0].ActionCode != "ISSUE" {
		return nil, NewEnvelopeError("first entry should contain an ISSUE transaction")
	}

	// Step 3b: Check the first entry contains a issuanceManifestSignedContent field
	if firstEntry.IssuanceManifestSignedContent == nil {
		return nil, NewEnvelopeError("first entry should contain an issuanceManifestSignedContent field")
	}

	// Step 4: verify the chain and collect all entries
	// We allocate the slice with the exact size needed
	allEntries := make([]*EnvelopeTransferChainEntry, len(envelopeTransferChain))

	// Start from the last entry and walk backwards to the first entry
	for i := len(envelopeTransferChain) - 1; i >= 0; i-- {
		currentEntryJWS := envelopeTransferChain[i]

		// Step 4a: Verify signature of the entry
		// Each entry in the chain is signed by the platform that created it.
		// This prevents a platform from tampering with an entry created by another platform (since they don't have the private key)

		currentPayloadBytes, _, _, err := crypto.VerifyJWSWithKeyProvider(
			string(currentEntryJWS),
			keyProvider,
			rootCAs,
		)
		if err != nil {
			return nil, WrapSignatureError(err, fmt.Sprintf("entry %d JWS verification failed", i))
		}

		// Parse the entry payload
		var currentEntry EnvelopeTransferChainEntry
		if err := json.Unmarshal(currentPayloadBytes, &currentEntry); err != nil {
			return nil, WrapEnvelopeError(err, fmt.Sprintf("failed to parse entry %d payload", i))
		}

		// Validate the entry has all the mandatory fields
		if err := currentEntry.ValidateStructure(i); err != nil {
			return nil, WrapEnvelopeError(err, fmt.Sprintf("entry %d validation failed", i))
		}

		// Step 4b: Verify that the platform that signed this entry matches the eblPlatform claimed in the entry payload.
		// This blocks transfers if any of the chain entries were signed by a different platform than
		// the platform claimed in the transfer chain entry (envelopeTransferChainEntry.eblPlatform)
		// If previous receiving platforms are functioning correctly they will not accept incorrectly addresssed envelopes
		// so this problem should only ever be detected in the latest transfer chain entry
		// (we check them all just in case).
		kp, ok := keyProvider.(KeyProviderWithLookup)
		if !ok {
			return nil, NewEnvelopeError("keyProvider must implement KeyProviderWithLookup for platform validation")
		}

		// Extract the key ID from the JWS header
		entryHeader, err := crypto.ParseJWSHeader(string(currentEntryJWS))
		if err != nil {
			return nil, WrapSignatureError(err, fmt.Sprintf("failed to parse entry %d header", i))
		}

		signingPlatform, err := kp.LookupPlatformByKeyID(context.Background(), entryHeader.KeyID)
		if err != nil {
			return nil, WrapSignatureError(err, fmt.Sprintf("failed to lookup platform for key %s in entry %d", entryHeader.KeyID, i))
		}

		if currentEntry.EblPlatform != signingPlatform {
			return nil, NewEnvelopeError(fmt.Sprintf(
				"entry %d was signed by platform %s (kid=%s) but claims eblPlatform %s",
				i, signingPlatform, entryHeader.KeyID, currentEntry.EblPlatform))
		}

		// Store the entry in the result slice
		allEntries[i] = &currentEntry

		// Step 4c: verify the chain link from this entry to the previous entry (if not the first entry)
		// this prevents an attacker from replacing a valid entry with a valid one from a different transfer.
		if i > 0 {
			previousEntryJWS := envelopeTransferChain[i-1]

			// Compute checksum of previous entry
			previousChecksum, err := crypto.Hash([]byte(previousEntryJWS))
			if err != nil {
				return nil, WrapEnvelopeError(err, fmt.Sprintf("failed to compute checksum for entry %d", i-1))
			}

			// current entry should reference previous entry's checksum

			if currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum == nil {
				return nil, NewEnvelopeError(fmt.Sprintf("entry %d is missing previousEnvelopeTransferChainEntrySignedContentChecksum", i))
			}

			if *currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum != previousChecksum {
				return nil, NewEnvelopeError(fmt.Sprintf("entry %d chain link broken: expected previous checksum %s, got %s",
					i, previousChecksum, *currentEntry.PreviousEnvelopeTransferChainEntrySignedContentChecksum))
			}
		}
	}

	// Step 5: Verify transport document checksum matches the manifest and is consistent across all entries
	// All entries must reference the same transport document - it cannot change during transfers
	firstChecksum := allEntries[0].TransportDocumentChecksum

	if firstChecksum != manifest.TransportDocumentChecksum {
		return nil, NewEnvelopeError(fmt.Sprintf("transport doc checksum in first transfer chain entry does not match manifest: expected %s, got %s",
			manifest.TransportDocumentChecksum, firstChecksum))
	}

	for i := 1; i < len(allEntries); i++ {
		if allEntries[i].TransportDocumentChecksum != firstChecksum {
			return nil, NewEnvelopeError(fmt.Sprintf("transport document checksum changed in entry %d: expected %s, got %s",
				i, firstChecksum, allEntries[i].TransportDocumentChecksum))
		}
	}

	// Step 6: Validate transaction sequence follows valid state transitions
	currentState := EnvelopeStateUnset
	for entryIdx, entry := range allEntries {
		for txIdx, tx := range entry.Transactions {
			nextState := EnvelopeState(tx.ActionCode)

			// First transaction must be ISSUE
			if currentState == EnvelopeStateUnset {
				if nextState != EnvelopeStateIssue {
					return nil, NewEnvelopeError(fmt.Sprintf(
						"first transaction must be ISSUE, got %s (entry %d, transaction %d)",
						tx.ActionCode, entryIdx, txIdx))
				}
				currentState = nextState
				continue
			}

			// Validate the transition is allowed (no transitions are allowed after SURRENDER_FOR_AMENDMENT or SURRENDER_FOR_DELIVERY)
			if !isValidEnvelopeStateTransition(currentState, nextState) {
				return nil, NewEnvelopeError(fmt.Sprintf(
					"invalid state transition from %s to %s (entry %d, transaction %d)",
					currentState, nextState, entryIdx, txIdx))
			}

			currentState = nextState
		}
	}
	return allEntries, nil
}
