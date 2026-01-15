// transfer_chain.go provides the low level function used to create and sign transfer chain entries.
//
// The transfer chain represents the complete history of an eBL document, including issuance,
// transfers, endorsements, and surrenders across different eBL platforms.
// each entry in the transfer chain represents a batch of transactions that happened on a single platform.
//
// TODO improve validation using DCSA reference data to confirm valid ebl platforms, action codes etc.
package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
)

// EnvelopeTransferChainEntry represents a DCSA EnvelopeTransferChainEntry
// A transfer chain entry represents a batch of transactions that happened on a single platform.
// This is the payload that gets signed in EnvelopeTransferChainEntrySignedContent
type EnvelopeTransferChainEntry struct {

	// EblPlatform: The eBL platform code (e.g., "WAVE", "BOLE", "CARX") responsible for this entry
	EblPlatform string `json:"eblPlatform"`

	// TransportDocumentChecksum: SHA-256 of canonicalized transport document JSON
	TransportDocumentChecksum string `json:"transportDocumentChecksum"`

	// PreviousEnvelopeTransferChainEntrySignedContentChecksum: SHA-256 of previous entry JWS (omitted for first entry)
	// this is the checksum of the previous entry in the transfer chain, and should only be included if this is not the first entry in the transfer chain.
	// This ensures the integrity of the transfer chain.
	PreviousEnvelopeTransferChainEntrySignedContentChecksum *string `json:"previousEnvelopeTransferChainEntrySignedContentChecksum,omitempty"`

	// IssuanceManifestSignedContent: JWS of IssuanceManifest (required for first entry only)
	// The issuance manifest is created by the carrier when the eBL is issued and proves the integrity of the transport document and the issueTo party data.
	IssuanceManifestSignedContent *IssuanceManifestSignedContent `json:"issuanceManifestSignedContent,omitempty"`

	// ControlTrackingRegistry: URI of CTR (optional, only in first entry). Example: https://ctr.dcsa.org/v1
	ControlTrackingRegistry *string `json:"controlTrackingRegistry,omitempty"`

	// Transactions: List of transactions (at least one required)
	Transactions []Transaction `json:"transactions"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (e *EnvelopeTransferChainEntry) Validate() error {
	if e.EblPlatform == "" {
		return fmt.Errorf("eblPlatform is required")
	}
	if e.TransportDocumentChecksum == "" {
		return fmt.Errorf("transportDocumentChecksum is required")
	}
	if len(e.Transactions) == 0 {
		return fmt.Errorf("at least one transaction is required")
	}

	// Validate first vs subsequent entry rules
	hasIssuanceManifest := e.IssuanceManifestSignedContent != nil
	hasPreviousEntry := e.PreviousEnvelopeTransferChainEntrySignedContentChecksum != nil

	if hasIssuanceManifest && hasPreviousEntry {
		return fmt.Errorf("entry cannot have both issuanceManifestSignedContent and previousEnvelopeTransferChainEntrySignedContentChecksum")
	}

	if !hasIssuanceManifest && !hasPreviousEntry {
		return fmt.Errorf("entry must have either issuanceManifestSignedContent (first entry) or previousEnvelopeTransferChainEntrySignedContentChecksum (subsequent entry)")
	}

	// First entry specific validation
	if hasIssuanceManifest {
		// TODO - is there a register of valid CTRs - or is this something that is configured at service start up?
		if e.ControlTrackingRegistry != nil {
			// Validate CTR URL format
			if _, err := url.Parse(*e.ControlTrackingRegistry); err != nil {
				return fmt.Errorf("invalid controlTrackingRegistry URL: %w", err)
			}
		}
	}

	// Subsequent entry specific validation
	if hasPreviousEntry {
		if e.ControlTrackingRegistry != nil {
			return fmt.Errorf("controlTrackingRegistry should only be present in first entry")
		}
	}

	// Validate each transaction
	for i, tx := range e.Transactions {
		if err := tx.Validate(); err != nil {
			return fmt.Errorf("transaction[%d]: %w", i, err)
		}
	}

	return nil
}

// Transaction represents a DCSA Transaction in the envelope transfer chain
// (the ebl platform is required to record transactions such as issuance, endorsements and surrender)
type Transaction struct {

	// actionCode: The transaction type (ISSUE, TRANSFER, ENDORSE, SURRENDER_FOR_DELIVERY, etc.)
	ActionCode string `json:"actionCode"`

	// actor: The legal entity (party) performing the action (required)
	Actor ActorParty `json:"actor"`

	// recipient: The party receiving the action (optional for some action codes like SIGN)
	Recipient *RecipientParty `json:"recipient,omitempty"`

	// actionDateTime: RFC3339 timestamp (UTC) when the transaction was created
	ActionDateTime string `json:"actionDateTime"` // RFC3339 format with millisecond precision

	// reasonCode: Reason code for SURRENDER_FOR_AMENDMENT (optional)
	// SWTP (Switch to paper)
	// COD (Change of destination)
	// SWI (Switch BL)
	ReasonCode *string `json:"reasonCode,omitempty"`

	// comments: Free text comment (optional)
	Comments *string `json:"comments,omitempty"`

	// auditReference: Audit identifier from eBL Solution Provider (optional)
	AuditReference *string `json:"auditReference,omitempty"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (t *Transaction) Validate() error {
	if t.ActionCode == "" {
		return fmt.Errorf("actionCode is required")
	}
	if err := t.Actor.Validate(); err != nil {
		return fmt.Errorf("actor: %w", err)
	}
	if t.ActionDateTime == "" {
		return fmt.Errorf("actionDateTime is required")
	}
	// Recipient is optional (e.g., for SIGN action code)
	if t.Recipient != nil {
		if err := t.Recipient.Validate(); err != nil {
			return fmt.Errorf("recipient: %w", err)
		}
	}
	return nil
}

// ActorParty represents a legal entity (party) performing a transaction action in the transfer chain.
// Actor parties are used in the EBL_ISS (issuance) and EBL_PINT (platform interoperability) specifications.
type ActorParty struct {

	// PartyName: Name of the party (required)
	PartyName string `json:"partyName"`

	// EblPlatform: The eBL platform code (required) - BOLE, WAVE etc (c.f https://github.com/dcsaorg/DCSA-OpenAPI/tree/master/reference-data)
	EblPlatform string `json:"eblPlatform"`

	// IdentifyingCodes: List of identifying codes (at least one required)
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes"`

	// TaxLegalReferences: List of tax/legal references (optional)
	TaxLegalReferences []TaxLegalReference `json:"taxLegalReferences,omitempty"`

	// RepresentedParty: An identifier issued by the eBL Solution Provider, used for auditing purposes to verify that the endorsement chain action has been securely recorded.
	RepresentedParty *RepresentedActorParty `json:"representedParty,omitempty"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (a *ActorParty) Validate() error {
	if a.PartyName == "" {
		return fmt.Errorf("partyName is required")
	}
	if a.EblPlatform == "" {
		return fmt.Errorf("eblPlatform is required")
	}
	if len(a.IdentifyingCodes) == 0 {
		return fmt.Errorf("at least one identifyingCode is required")
	}
	for i, code := range a.IdentifyingCodes {
		if err := code.Validate(); err != nil {
			return fmt.Errorf("identifyingCodes[%d]: %w", i, err)
		}
	}
	if a.RepresentedParty != nil {
		if err := a.RepresentedParty.Validate(); err != nil {
			return fmt.Errorf("representedParty: %w", err)
		}
	}
	return nil
}

// RecipientParty represents the party receiving a transaction action
type RecipientParty struct {

	// PartyName: Name of the party (required)
	PartyName string `json:"partyName"`

	// EblPlatform: The eBL platform code (required)
	EblPlatform string `json:"eblPlatform"`

	// IdentifyingCodes: List of identifying codes (at least one required)

	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes"`

	// TaxLegalReferences: List of tax/legal references (optional)
	TaxLegalReferences []TaxLegalReference `json:"taxLegalReferences,omitempty"`

	// RepresentedParty: Party on whose behalf the action was directed (optional)
	RepresentedParty *RepresentedRecipientParty `json:"representedParty,omitempty"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (r *RecipientParty) Validate() error {
	if r.PartyName == "" {
		return fmt.Errorf("partyName is required")
	}
	if r.EblPlatform == "" {
		return fmt.Errorf("eblPlatform is required")
	}
	if len(r.IdentifyingCodes) == 0 {
		return fmt.Errorf("at least one identifyingCode is required")
	}
	for i, code := range r.IdentifyingCodes {
		if err := code.Validate(); err != nil {
			return fmt.Errorf("identifyingCodes[%d]: %w", i, err)
		}
	}
	if r.RepresentedParty != nil {
		if err := r.RepresentedParty.Validate(); err != nil {
			return fmt.Errorf("representedParty: %w", err)
		}
	}
	return nil
}

// RepresentedActorParty represents the party on whose behalf the actor performed the action
type RepresentedActorParty struct {

	// PartyName: Name of the party (required)
	PartyName string `json:"partyName"`

	// IdentifyingCodes: List of identifying codes (optional)
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes,omitempty"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (r *RepresentedActorParty) Validate() error {
	if r.PartyName == "" {
		return fmt.Errorf("partyName is required")
	}
	// IdentifyingCodes are optional for represented parties
	for i, code := range r.IdentifyingCodes {
		if err := code.Validate(); err != nil {
			return fmt.Errorf("identifyingCodes[%d]: %w", i, err)
		}
	}
	return nil
}

// RepresentedRecipientParty represents the party on whose behalf the action was directed
type RepresentedRecipientParty struct {

	// PartyName: Name of the party (required)
	PartyName string `json:"partyName"`

	// IdentifyingCodes: List of identifying codes (optional)
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes,omitempty"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (r *RepresentedRecipientParty) Validate() error {
	if r.PartyName == "" {
		return fmt.Errorf("partyName is required")
	}
	// IdentifyingCodes are optional for represented parties
	for i, code := range r.IdentifyingCodes {
		if err := code.Validate(); err != nil {
			return fmt.Errorf("identifyingCodes[%d]: %w", i, err)
		}
	}
	return nil
}

// IdentifyingCode represents a code that uniquely identifies a party
type IdentifyingCode struct {

	// CodeListProvider: The provider of the code list (this can be a platform code like "WAVE", or a code list provider like "DCSA", "GLEIF", "W3C", "DNB")
	CodeListProvider string `json:"codeListProvider"`

	// PartyCode: Code to identify the party as provided by the code list provider
	PartyCode string `json:"partyCode"`

	// codeListName: The name of the code list, code generation mechanism or code authority for the partyCode.
	// Example values could be: DID (codeListProvider W3C), LEI (codeListProvider GLEIF), DUNS (codeListProvider Dunn and Bradstreet) etc.
	CodeListName *string `json:"codeListName,omitempty"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (i *IdentifyingCode) Validate() error {
	if i.CodeListProvider == "" {
		return fmt.Errorf("codeListProvider is required")
	}
	if i.PartyCode == "" {
		return fmt.Errorf("partyCode is required")
	}
	return nil
}

// TaxLegalReference uniquely identifies a party for tax and/or legal purposes in accordance with the relevant jurisdiction.
//
// Examples:
// - EORI (Economic Operators Registration and Identification)
// - PAN (Permanent Account Number - India)
// - GSTIN (Goods and Services Tax Identification Number - India)
// - CVR (Central Business Register - Denmark)
// - etc
type TaxLegalReference struct {

	// Type: The reference type code (e.g., "PAN", "EORI", "GSTIN", "CVR")
	Type string `json:"type"`

	// CountryCode: ISO 3166-1 alpha-2 country code
	CountryCode string `json:"countryCode"`

	// Value: The actual reference value
	Value string `json:"value"`
}

// SignWithEd25519AndX5C creates the envelopeTransferChainEntrySignedContent JWS string using Ed25519
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeTransferChain
func (e *EnvelopeTransferChainEntry) SignWithEd25519AndX5C(privateKey ed25519.PrivateKey, keyID string, certChain []*x509.Certificate) (EnvelopeTransferChainEntrySignedContent, error) {
	jsonBytes, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("failed to serialize envelope transfer chain entry: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithEd25519AndX5C)
	jws, err := SignJSONWithEd25519AndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign envelope transfer chain entry: %w", err)
	}

	return EnvelopeTransferChainEntrySignedContent(jws), nil
}

// SignWithEd25519 creates the envelopeTransferChainEntrySignedContent JWS string using Ed25519 (no x5c header)
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeTransferChain
func (e *EnvelopeTransferChainEntry) SignWithEd25519(privateKey ed25519.PrivateKey, keyID string) (EnvelopeTransferChainEntrySignedContent, error) {
	jsonBytes, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("failed to serialize envelope transfer chain entry: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithEd25519)
	jws, err := SignJSONWithEd25519(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign envelope transfer chain entry: %w", err)
	}

	return EnvelopeTransferChainEntrySignedContent(jws), nil
}

// SignWithRSAAndX5C creates the envelopeTransferChainEntrySignedContent JWS string using RSA
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeTransferChain
func (e *EnvelopeTransferChainEntry) SignWithRSAAndX5C(privateKey *rsa.PrivateKey, keyID string, certChain []*x509.Certificate) (EnvelopeTransferChainEntrySignedContent, error) {
	jsonBytes, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("failed to serialize envelope transfer chain entry: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithRSAAndX5C)
	jws, err := SignJSONWithRSAAndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign envelope transfer chain entry: %w", err)
	}

	return EnvelopeTransferChainEntrySignedContent(jws), nil
}

// SignWithRSA creates the envelopeTransferChainEntrySignedContent JWS string using RSA (no x5c header)
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeTransferChain
func (e *EnvelopeTransferChainEntry) SignWithRSA(privateKey *rsa.PrivateKey, keyID string) (EnvelopeTransferChainEntrySignedContent, error) {
	jsonBytes, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("failed to serialize envelope transfer chain entry: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithRSA)
	jws, err := SignJSONWithRSA(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign envelope transfer chain entry: %w", err)
	}

	return EnvelopeTransferChainEntrySignedContent(jws), nil
}

// EnvelopeTransferChainEntryBuilder helps build transfer chain entries and handles checksum calculations, validations and so on.
type EnvelopeTransferChainEntryBuilder struct {
	// isFirstEntry: Entry position in chain - the first entry must include an issuance manifest,
	// all subsequent entries must include a previous entry checksum
	isFirstEntry bool

	// transportDocumentChecksum: SHA-256 checksum of the canonical transport document
	// This should be the validated checksum from the carrier's IssuanceManifest
	transportDocumentChecksum string

	// eblPlatform: ebl platform code responsible for this entry
	eblPlatform string

	// issuanceManifestSignedContent: JWS of IssuanceManifest (required for first entry only)
	issuanceManifestSignedContent *IssuanceManifestSignedContent

	// controlTrackingRegistry: URI of CTR (optional, only in first entry). Example: https://ctr.dcsa.org/v1
	controlTrackingRegistry *string

	// previousEnvelopeTransferChainEntrySignedContent: JWS of previous entry in the transfer chain (required for subsequent entries only)
	previousEnvelopeTransferChainEntrySignedContent EnvelopeTransferChainEntrySignedContent

	// transactions: List of transactions for this entry
	transactions []Transaction
}

// NewFirstEnvelopeTransferChainEntryBuilder creates a builder for the the first entry in the transfer chain.
//
// The first entry requires the issuanceManifestSignedContent field to be set.
// (previousEnvelopeTransferChainEntrySignedContent is required only for subsequent entries)
func NewFirstEnvelopeTransferChainEntryBuilder(issuanceManifestSignedContent IssuanceManifestSignedContent) *EnvelopeTransferChainEntryBuilder {
	return &EnvelopeTransferChainEntryBuilder{
		isFirstEntry:                  true,
		issuanceManifestSignedContent: &issuanceManifestSignedContent,
	}
}

// NewSubsequentEnvelopeTransferChainEntryBuilder creates a builder for a subsequent entry in the transfer chain.
// Use this builder for all entries apart from the first entry in the transfer chain (see NewFirstEnvelopeTransferChainEntryBuilder)
//
// The previous entry checksum (previousEnvelopeTransferChainEntrySignedContentChecksum)
// will be calculated automatically in based on the previousJWS provided to this function during Build().
func NewSubsequentEnvelopeTransferChainEntryBuilder(previousJWS EnvelopeTransferChainEntrySignedContent) *EnvelopeTransferChainEntryBuilder {
	return &EnvelopeTransferChainEntryBuilder{
		isFirstEntry: false,
		previousEnvelopeTransferChainEntrySignedContent: previousJWS,
	}
}

// WithTransportDocumentChecksum sets the pre-computed transport document checksum.
//
// Use the validated checksum from the carrier's IssuanceManifest.
// The checksum should have been validated when the eBL platform first received the issuance request.
func (b *EnvelopeTransferChainEntryBuilder) WithTransportDocumentChecksum(checksum string) *EnvelopeTransferChainEntryBuilder {
	b.transportDocumentChecksum = checksum
	return b
}

// WithEBLPlatform sets the eBL platform code (e.g., "WAVE", "BOLE", "CARX")
func (b *EnvelopeTransferChainEntryBuilder) WithEBLPlatform(platform string) *EnvelopeTransferChainEntryBuilder {
	b.eblPlatform = platform
	return b
}

// WithTransaction adds a transaction to this entry
// You can call this multiple times to add multiple transactions to a single entry
func (b *EnvelopeTransferChainEntryBuilder) WithTransaction(transaction Transaction) *EnvelopeTransferChainEntryBuilder {
	b.transactions = append(b.transactions, transaction)
	return b
}

// WithTransactions sets all transactions for this entry at once
func (b *EnvelopeTransferChainEntryBuilder) WithTransactions(transactions []Transaction) *EnvelopeTransferChainEntryBuilder {
	b.transactions = transactions
	return b
}

// WithControlTrackingRegistry sets the CTR URI (optional, only for first entry)
// Example: "https://ctr.dcsa.org/v1"
func (b *EnvelopeTransferChainEntryBuilder) WithControlTrackingRegistry(uri string) *EnvelopeTransferChainEntryBuilder {
	b.controlTrackingRegistry = &uri
	return b
}

// Build creates the EnvelopeTransferChainEntry with the required checksums calculated.
//
// the build process is as follows:
//   - If this is a subsequent entry, calculate the checksum of the previous entry JWS
//   - Assemble the EnvelopeTransferChainEntry struct
//   - Validate the entry
//
// Note it is necessary to include the transport document checksum in every entry in the transfer chain
// to prevent replay attacks (where an attacker replaces the last entry in the chain with a previous entry from a different chain).
// The transport document checksum is validated when the eBL platform first receives the issuance request and is unchanged for the lifetime of the eBL.
//
// returns *EnvelopeTransferChainEntry: Ready to sign
func (b *EnvelopeTransferChainEntryBuilder) Build() (*EnvelopeTransferChainEntry, error) {

	// check required builder fields
	if b.transportDocumentChecksum == "" {
		return nil, fmt.Errorf("transport document checksum is required - use WithTransportDocumentChecksum() or WithTransportDocument()")
	}

	if b.eblPlatform == "" {
		return nil, fmt.Errorf("eBL platform is required - use WithEBLPlatform()")
	}

	if len(b.transactions) == 0 {
		return nil, fmt.Errorf("at least one transaction is required - use WithTransaction()")
	}

	// Build the entry using the pre-computed checksum
	entry := &EnvelopeTransferChainEntry{
		EblPlatform:               b.eblPlatform,
		TransportDocumentChecksum: b.transportDocumentChecksum,
		Transactions:              b.transactions,
	}

	// Add optional fields (Validate() will check they're used correctly)
	entry.IssuanceManifestSignedContent = b.issuanceManifestSignedContent
	entry.ControlTrackingRegistry = b.controlTrackingRegistry

	// Calculate and add previous entry checksum if provided
	if b.previousEnvelopeTransferChainEntrySignedContent != "" {
		// this is a checksum of the JWS string of the previous entry in the transfer chain.
		prevChecksum, err := Hash([]byte(b.previousEnvelopeTransferChainEntrySignedContent))
		if err != nil {
			return nil, fmt.Errorf("failed to hash previous entry: %w", err)
		}
		entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum = &prevChecksum
	}

	// Validate the final entry (this will check first/subsequent entry rules)
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("invalid transfer chain entry: %w", err)
	}

	return entry, nil
}
