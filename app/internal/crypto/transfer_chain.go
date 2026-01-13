// transfer_chain.go implements the DCSA EBL_PINT specification for creating and signing transfer chain entries.
//
// The transfer chain represents the complete history of an eBL document, including issuance,
// transfers, endorsements, and surrenders across different eBL platforms.

package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
)

// EnvelopeTransferChainEntry represents a DCSA EnvelopeTransferChainEntry
// This is the payload that gets signed in EnvelopeTransferChainEntrySignedContent
type EnvelopeTransferChainEntry struct {

	// EblPlatform: The eBL platform code (e.g., "WAVE", "BOLE", "CARX")
	EblPlatform string `json:"eblPlatform"`

	// ransportDocumentChecksum: SHA-256 of canonicalized transport document JSON
	TransportDocumentChecksum string `json:"transportDocumentChecksum"`

	// PreviousEnvelopeTransferChainEntrySignedContentChecksum: SHA-256 of previous entry JWS (omitted for first entry)
	PreviousEnvelopeTransferChainEntrySignedContentChecksum *string `json:"previousEnvelopeTransferChainEntrySignedContentChecksum,omitempty"`

	// IssuanceManifestSignedContent: JWS of IssuanceManifest (required for first entry only)
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
