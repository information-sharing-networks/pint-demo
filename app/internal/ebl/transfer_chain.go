package ebl

// transfer_chain.go provides the builders for transfer chain entries.
//
// The transfer chain represents the complete history of an eBL document, including issuance,
// transfers, endorsements, and surrenders across different eBL platforms.
// Each entry in the transfer chain represents a batch of transactions that happened on a single platform.
//
// for standard usage you can use the high level functions in envelope_transfer.go instead (c.f CreateTransferChainEntry)
// as this will handle building and signing the transfer chain entry for you.

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// EnvelopeTransferChainEntry represents a DCSA EnvelopeTransferChainEntry
// A transfer chain entry represents a batch of transactions that happened on a single platform.
// This is the payload that gets signed in EnvelopeTransferChainEntrySignedContent
type EnvelopeTransferChainEntry struct {

	// EblPlatform: The eBL platform code (e.g., "WAVE", "BOLE", "CARX") responsible for this entry
	EblPlatform string `json:"eblPlatform"`

	// TransportDocumentChecksum: SHA-256 of canonicalized transport document JSON
	// this should not change for the lifetime of the eBL.
	TransportDocumentChecksum string `json:"transportDocumentChecksum"`

	// PreviousEnvelopeTransferChainEntrySignedContentChecksum: SHA-256 of previous entry JWS (omitted for first entry)
	// this is the checksum of the previous entry in the transfer chain, and should only be included if this is not the first entry in the transfer chain.
	// This ensures the integrity of the transfer chain.
	PreviousEnvelopeTransferChainEntrySignedContentChecksum *string `json:"previousEnvelopeTransferChainEntrySignedContentChecksum,omitempty"`

	// IssuanceManifestSignedContent: JWS of IssuanceManifest (required for first entry only)
	// The issuance manifest is created and signed the carrier when the eBL is issued and proves the integrity of the transport document and the issueTo party data.
	// It should not change for the lifetime of the eBL.
	IssuanceManifestSignedContent *IssuanceManifestSignedContent `json:"issuanceManifestSignedContent,omitempty"`

	// ControlTrackingRegistry: URI of CTR (optional, only in first entry). Example: https://ctr.dcsa.org/v1
	ControlTrackingRegistry *string `json:"controlTrackingRegistry,omitempty"`

	// Transactions: List of transactions (at least one required)
	Transactions []Transaction `json:"transactions"`
}

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (e *EnvelopeTransferChainEntry) ValidateStructure(entryNumber int) error {
	if e.EblPlatform == "" {
		return NewEnvelopeError("eblPlatform is required")
	}
	if e.TransportDocumentChecksum == "" {
		return NewEnvelopeError("transportDocumentChecksum is required")
	}
	if len(e.Transactions) == 0 {
		return NewEnvelopeError("at least one transaction is required")
	}

	// Validate first vs subsequent entry rules
	hasIssuanceManifest := e.IssuanceManifestSignedContent != nil
	hasPreviousEntry := e.PreviousEnvelopeTransferChainEntrySignedContentChecksum != nil
	isFirstEntry := entryNumber == 0

	if isFirstEntry && !hasIssuanceManifest {
		return NewEnvelopeError("issuanceManifestSignedContent is required for first entry")
	}

	if !isFirstEntry && !hasPreviousEntry {
		return NewEnvelopeError("previousEnvelopeTransferChainEntrySignedContentChecksum is required on all entries apart from the first entry")
	}

	if hasIssuanceManifest && hasPreviousEntry {
		return NewEnvelopeError("entry cannot have both issuanceManifestSignedContent and previousEnvelopeTransferChainEntrySignedContentChecksum")
	}

	// First entry specific validation
	if hasIssuanceManifest {
		// TODO - is there a register of valid CTRs - or is this something that is configured at service start up?
		if e.ControlTrackingRegistry != nil {
			// Validate CTR URL format
			if _, err := url.Parse(*e.ControlTrackingRegistry); err != nil {
				return WrapEnvelopeError(err, "invalid controlTrackingRegistry URL")
			}
		}
	}

	// Subsequent entry specific validation
	if hasPreviousEntry {
		if e.ControlTrackingRegistry != nil {
			return NewEnvelopeError("controlTrackingRegistry should only be present in first entry")
		}
	}

	// Validate each transaction
	for i, tx := range e.Transactions {
		if err := tx.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("transaction[%d]", i))
		}
	}

	return nil
}

// Transaction represents a DCSA Transaction in the envelope transfer chain
// (the ebl platform is required to record transactions such as issuance, endorsements and surrender)
type Transaction struct {

	// actionCode: The transaction type (ISSUE, TRANSFER, ENDORSE, SURRENDER_FOR_DELIVERY, etc.)
	ActionCode ActionCode `json:"actionCode"`

	// actor: The legal entity (party) performing the action (required)
	Actor ActorParty `json:"actor"`

	// recipient: The party receiving the action (optional for some action codes like SIGN)
	Recipient *RecipientParty `json:"recipient,omitempty"`

	// actionDateTime: RFC3339 timestamp (UTC) when the transaction was created
	ActionDateTime string `json:"actionDateTime"` // RFC3339 format with millisecond precision

	// reasonCode: Reason code for SURRENDER_FOR_AMENDMENT (optional)
	// Possible values: SWTP (Switch to paper), COD (Change of destination), SWI (Switch BL)
	ReasonCode *SurrenderForAmendmentReasonCode `json:"reasonCode,omitempty"`

	// comments: Free text comment (optional)
	Comments *string `json:"comments,omitempty"`

	// auditReference: Audit identifier from eBL Solution Provider (optional)
	AuditReference *string `json:"auditReference,omitempty"`
}

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (t *Transaction) ValidateStructure() error {
	if t.ActionCode == "" {
		return NewEnvelopeError("actionCode is required")
	}
	if err := t.Actor.ValidateStructure(); err != nil {
		return WrapEnvelopeError(err, "actor")
	}
	if t.ActionDateTime == "" {
		return NewEnvelopeError("actionDateTime is required")
	}

	// SIGN and BLANK_ENDORSE must not have a recipient; all other action codes require one
	switch t.ActionCode {
	case ActionCodeSign, ActionCodeBlankEndorse:
		if t.Recipient != nil {
			return NewEnvelopeError(fmt.Sprintf("%s must not have a recipient", t.ActionCode))
		}
	default:
		if t.Recipient == nil {
			return NewEnvelopeError(fmt.Sprintf("%s requires a recipient", t.ActionCode))
		}
		if err := t.Recipient.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, "recipient")
		}
	}

	// reasonCode is only applicable for SURRENDER_FOR_AMENDMENT
	if t.ReasonCode != nil && t.ActionCode != ActionCodeSurrenderForAmendment {
		return NewEnvelopeError(fmt.Sprintf("reasonCode is only applicable for %s, not %s", ActionCodeSurrenderForAmendment, t.ActionCode))
	}

	return nil
}

// identifyingCodesMatch returns true if at least one IdentifyingCode from a matches one from b
// (same codeListProvider and partyCode).
// TODO: need to agree the rules for this - should it match all? should it be configurable?
func identifyingCodesMatch(a, b []IdentifyingCode) bool {
	for _, codeA := range a {
		for _, codeB := range b {
			if codeA.CodeListProvider == codeB.CodeListProvider && codeA.PartyCode == codeB.PartyCode {
				return true
			}
		}
	}
	return false
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

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (a *ActorParty) ValidateStructure() error {
	if a.PartyName == "" {
		return NewEnvelopeError("partyName is required")
	}
	if a.EblPlatform == "" {
		return NewEnvelopeError("eblPlatform is required")
	}
	if len(a.IdentifyingCodes) == 0 {
		return NewEnvelopeError("at least one identifyingCode is required")
	}
	for i, code := range a.IdentifyingCodes {
		if err := code.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("identifyingCodes[%d]", i))
		}
	}
	if a.RepresentedParty != nil {
		if err := a.RepresentedParty.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, "representedParty")
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

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (r *RecipientParty) ValidateStructure() error {
	if r.PartyName == "" {
		return NewEnvelopeError("partyName is required")
	}
	if r.EblPlatform == "" {
		return NewEnvelopeError("eblPlatform is required")
	}
	if len(r.IdentifyingCodes) == 0 {
		return NewEnvelopeError("at least one identifyingCode is required")
	}
	for i, code := range r.IdentifyingCodes {
		if err := code.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("identifyingCodes[%d]", i))
		}
	}
	if r.RepresentedParty != nil {
		if err := r.RepresentedParty.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, "representedParty")
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

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (r *RepresentedActorParty) ValidateStructure() error {
	if r.PartyName == "" {
		return fmt.Errorf("partyName is required")
	}
	// IdentifyingCodes are optional for represented parties
	for i, code := range r.IdentifyingCodes {
		if err := code.ValidateStructure(); err != nil {
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

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (r *RepresentedRecipientParty) ValidateStructure() error {
	if r.PartyName == "" {
		return fmt.Errorf("partyName is required")
	}
	// IdentifyingCodes are optional for represented parties
	for i, code := range r.IdentifyingCodes {
		if err := code.ValidateStructure(); err != nil {
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

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (i *IdentifyingCode) ValidateStructure() error {
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

// Sign creates the EnvelopeTransferChainEntrySignedContent JWS string.
//
// The privateKey can be either ed25519.PrivateKey or *rsa.PrivateKey.
// If certChain is provided, the x5c header will be included in the JWS for non-repudiation.
//
// Returns a JWS compact serialization string ready to include in Envelope.envelopeTransferChain
func (e *EnvelopeTransferChainEntry) Sign(privateKey any, certChain []*x509.Certificate) (EnvelopeTransferChainEntrySignedContent, error) {
	// Marshal to JSON
	jsonBytes, err := json.Marshal(e)
	if err != nil {
		return "", WrapInternalError(err, "failed to marshal transfer chain entry")
	}

	// Sign
	jws, err := crypto.SignJSON(jsonBytes, privateKey, certChain)
	if err != nil {
		return "", WrapSignatureError(err, "failed to sign transfer chain entry")
	}

	return EnvelopeTransferChainEntrySignedContent(jws), nil
}

// TransferChainEntryInput contains the data needed to create a transfer chain entry.
//
// Note that there are conditional fields:
//   - When IsFirstEntry is true, IssuanceManifestSignedContent is required and PreviousEnvelopeTransferChainEntrySignedContent should not be provided.
//   - When IsFirstEntry is false, PreviousEnvelopeTransferChainEntrySignedContent is required and IssuanceManifestSignedContent should not be provided.
type TransferChainEntryInput struct {

	// TransportDocumentChecksum is the SHA-256 checksum of the canonical transport document.
	// This should be the validated checksum from the carrier's IssuanceManifest.
	TransportDocumentChecksum string

	// EBLPlatform is the platform code (e.g., "WAVE", "BOLE", "CARX")
	EBLPlatform string

	// IsFirstEntry indicates if this is the first entry in the chain.
	IsFirstEntry bool

	// IssuanceManifestSignedContent is required for the first entry only.
	IssuanceManifestSignedContent *IssuanceManifestSignedContent

	// ControlTrackingRegistry is optional and only for the first entry.
	// Example: "https://ctr.example.org/v1"
	ControlTrackingRegistry *string

	// PreviousEnvelopeTransferChainEntrySignedContent is required for subsequent entries (not first entry).
	PreviousEnvelopeTransferChainEntrySignedContent EnvelopeTransferChainEntrySignedContent

	// Transactions is the list of transactions for this entry (at least one required).
	Transactions []Transaction
}

// createTransferChainEntrySignedContent creates and signs a transfer chain entry.
//
// Parameters:
//   - input: The data for the transfer chain entry (transport document checksum, platform, transactions, etc.)
//   - privateKey: The platform's private key (ed25519.PrivateKey or *rsa.PrivateKey)
//   - certChain: Optional X.509 certificate chain. Pass nil to omit x5c header.
//
// Including x5c with EV/OV certificate is recommended for non-repudiation (enables offline verification).
//
// Returns the JWS signed transfer chain entry ready to include in the envelope transfer chain.
func createTransferChainEntrySignedContent(
	input TransferChainEntryInput,
	privateKey any,
	certChain []*x509.Certificate,
) (EnvelopeTransferChainEntrySignedContent, error) {

	// Step 1: Validate input
	if input.TransportDocumentChecksum == "" {
		return "", NewEnvelopeError("transport document checksum is required")
	}
	if input.EBLPlatform == "" {
		return "", NewEnvelopeError("eBL platform is required")
	}
	if len(input.Transactions) == 0 {
		return "", NewEnvelopeError("at least one transaction is required")
	}

	// check first vs subsequent entry requirements
	if input.IsFirstEntry {
		if input.IssuanceManifestSignedContent == nil {
			return "", NewEnvelopeError("issuance manifest is required for first entry")
		}
		if input.PreviousEnvelopeTransferChainEntrySignedContent != "" {
			return "", NewEnvelopeError("previous entry JWS should not be provided for first entry")
		}
	} else {
		if input.PreviousEnvelopeTransferChainEntrySignedContent == "" {
			return "", NewEnvelopeError("previous entry JWS is required for subsequent entries")
		}
		if input.IssuanceManifestSignedContent != nil {
			return "", NewEnvelopeError("issuance manifest should only be provided for first entry")
		}
		if input.ControlTrackingRegistry != nil {
			return "", NewEnvelopeError("control tracking registry should only be provided for first entry")
		}
	}

	// Step 2: Build the transfer chain entry using the builder
	var builder *EnvelopeTransferChainEntryBuilder

	if input.IsFirstEntry {
		builder = NewFirstEnvelopeTransferChainEntryBuilder(*input.IssuanceManifestSignedContent)
		// If provided, CTR is only included in the first entry.
		if input.ControlTrackingRegistry != nil {
			builder.WithControlTrackingRegistry(*input.ControlTrackingRegistry)
		}
	} else {
		builder = NewSubsequentEnvelopeTransferChainEntryBuilder(input.PreviousEnvelopeTransferChainEntrySignedContent)
	}

	entry, err := builder.
		WithTransportDocumentChecksum(input.TransportDocumentChecksum).
		WithEBLPlatform(input.EBLPlatform).
		WithTransactions(input.Transactions).
		Build()

	if err != nil {
		return "", WrapEnvelopeError(err, "failed to build transfer chain entry")
	}

	// Step 3: Sign the transfer chain entry with the platform's private key.
	// The keyID is automatically computed inside the Sign method.
	signedContent, err := entry.Sign(privateKey, certChain)
	if err != nil {
		return "", WrapEnvelopeError(err, "failed to sign transfer chain entry")
	}

	return signedContent, nil
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
//
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
		return nil, NewInternalError("transport document checksum is required - use WithTransportDocumentChecksum() or WithTransportDocument()")
	}

	if b.eblPlatform == "" {
		return nil, NewInternalError("eBL platform is required - use WithEBLPlatform()")
	}

	if len(b.transactions) == 0 {
		return nil, NewInternalError("at least one transaction is required - use WithTransaction()")
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
		prevChecksum, err := crypto.Hash([]byte(b.previousEnvelopeTransferChainEntrySignedContent))
		if err != nil {
			return nil, WrapInternalError(err, "failed to crypto.Hash previous entry")
		}
		entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum = &prevChecksum
	}

	if b.isFirstEntry && entry.IssuanceManifestSignedContent == nil {
		return nil, NewInternalError("IssuanceManifestSignedContent is required for first entry")
	}
	if !b.isFirstEntry && entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum == nil {
		return nil, NewInternalError("PreviousEnvelopeTransferChainEntrySignedContentChecksum is required in all entries apart from the first entry")
	}
	if entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum != nil && entry.IssuanceManifestSignedContent != nil {
		return nil, NewInternalError("entry cannot have both issuance manifest and previous entry checksum")
	}

	// Validate CTR rules
	if entry.ControlTrackingRegistry != nil {
		if !b.isFirstEntry {
			return nil, NewEnvelopeError("controlTrackingRegistry should only be present in first entry")
		}
		// Validate CTR URL format
		if _, err := url.Parse(*entry.ControlTrackingRegistry); err != nil {
			return nil, WrapEnvelopeError(err, "invalid controlTrackingRegistry URL")
		}
	}

	return entry, nil
}
