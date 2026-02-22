package ebl

import "fmt"

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
		return NewEnvelopeError("eBLPlatform is required")
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
		return NewEnvelopeError("eBLPlatform is required")
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
