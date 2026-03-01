package ebl

import "fmt"

// ActorParty is the party performing an action (e.g. endorser, transferor).
type ActorParty struct {

	// PartyName is the name of the party (e.g. "Maersk").
	PartyName string `json:"partyName"`

	// EblPlatform is the eBL platform code of the party (e.g. "WAVE", "CARX").
	EblPlatform string `json:"eblPlatform"`

	// IdentifyingCodes are the codes that uniquely identify the party.
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes"`

	// TaxLegalReferences are the tax and legal references for the party.
	TaxLegalReferences []TaxLegalReference `json:"taxLegalReferences,omitempty"`

	// RepresentedParty is the party on whose behalf the actor performed the action (optional)
	RepresentedParty *RepresentedActorParty `json:"representedParty,omitempty"`
}

// ValidateStructure checks the structure of the actor party and returns an error if it is invalid.
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
	for i, ref := range a.TaxLegalReferences {
		if err := ref.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("taxLegalReferences[%d]", i))
		}
	}
	if a.RepresentedParty != nil {
		if err := a.RepresentedParty.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, "representedParty")
		}
	}
	return nil
}

// RepresentedActorParty is the party on whose behalf the actor performed the action.
type RepresentedActorParty struct {

	// PartyName is the name of the party e.g. "Maersk".
	PartyName string `json:"partyName"`

	// IdentifyingCodes are the codes that uniquely identify the party (optional)
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes,omitempty"`
}

// ValidateStructure checks the structure of the represented actor party and returns an error if it is invalid.
func (r *RepresentedActorParty) ValidateStructure() error {
	if r.PartyName == "" {
		return NewEnvelopeError("partyName is required")
	}
	for i, code := range r.IdentifyingCodes {
		if err := code.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("identifyingCodes[%d]", i))
		}
	}
	return nil
}

// RecipientParty is the party performing an action (e.g. endorser, transferor).
type RecipientParty struct {

	// PartyName is the name of the party (e.g. "Maersk").
	PartyName string `json:"partyName"`

	// EblPlatform is the eBL platform code of the party (e.g. "WAVE", "CARX").
	EblPlatform string `json:"eblPlatform"`

	// IdentifyingCodes are the codes that uniquely identify the party.
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes"`

	// TaxLegalReferences are the tax and legal references for the party.
	TaxLegalReferences []TaxLegalReference `json:"taxLegalReferences,omitempty"`

	// RepresentedParty is the party on whose behalf the actor performed the action (optional)
	RepresentedParty *RepresentedRecipientParty `json:"representedParty,omitempty"`
}

// ValidateStructure checks the structure of the recipient party and returns an error if it is invalid.
func (a *RecipientParty) ValidateStructure() error {
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
	for i, ref := range a.TaxLegalReferences {
		if err := ref.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("taxLegalReferences[%d]", i))
		}
	}
	if a.RepresentedParty != nil {
		if err := a.RepresentedParty.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, "representedParty")
		}
	}
	return nil
}

// RepresentedRecipientParty is the party on whose behalf the actor performed the action.
type RepresentedRecipientParty struct {

	// PartyName is the name of the party e.g. "Maersk".
	PartyName string `json:"partyName"`

	// IdentifyingCodes are the codes that uniquely identify the party (optional)
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes,omitempty"`
}

// ValidateStructure checks the structure of the represented recipient party and returns an error if it is invalid.
func (r *RepresentedRecipientParty) ValidateStructure() error {
	if r.PartyName == "" {
		return NewEnvelopeError("partyName is required")
	}
	for i, code := range r.IdentifyingCodes {
		if err := code.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("identifyingCodes[%d]", i))
		}
	}
	return nil
}

// IdentifyingCode represents a code that uniquely identifies a party.
type IdentifyingCode struct {

	// CodeListProvider is the provider of the code list (e.g. "WAVE", "DCSA", "GLEIF", "W3C", "DNB").
	CodeListProvider string `json:"codeListProvider"`

	// CodeListName is the name of the code list (e.g. "DID", "LEI", "DUNS") - optional
	CodeListName *string `json:"codeListName,omitempty"`

	// PartyCode is the code identifying the party as provided by the code list provider.
	PartyCode string `json:"partyCode"`
}

// ValidateStructure checks the structure of the identifying code and returns an error if it is invalid.
func (c *IdentifyingCode) ValidateStructure() error {
	if c.CodeListProvider == "" {
		return NewEnvelopeError("identifying code codeListProvider is required")
	}
	if c.PartyCode == "" {
		return NewEnvelopeError("identifying code partyCode is required")
	}
	return nil
}

// TaxLegalReference uniquely identifies a party for tax and/or legal purposes
// in accordance with the relevant jurisdiction (e.g. EORI, PAN, GSTIN, CVR).
type TaxLegalReference struct {

	// Type is the reference type code (e.g. "PAN", "EORI", "GSTIN", "CVR").
	Type string `json:"type"`

	// CountryCode is the ISO 3166-1 alpha-2 country code.
	CountryCode string `json:"countryCode"`

	// Value is the actual reference value.
	Value string `json:"value"`
}

// ValidateStructure checks the structure of the tax and legal reference and returns an error if it is invalid.
func (r *TaxLegalReference) ValidateStructure() error {
	if r.Type == "" {
		return NewEnvelopeError("tax and legal reference type is required")
	}
	if r.CountryCode == "" {
		return NewEnvelopeError("tax and legal reference countryCode is required")
	}
	if r.Value == "" {
		return NewEnvelopeError("tax and legal reference value is required")
	}
	return nil
}

type RecipientPartyBuilder struct {
	partyName          string
	eblPlatform        string
	identifyingCodes   []IdentifyingCode
	taxLegalReferences []TaxLegalReference
	representedParty   *RepresentedRecipientParty
}

func NewRecipientPartyBuilder(partyName, eblPlatform string) *RecipientPartyBuilder {
	return &RecipientPartyBuilder{
		partyName:   partyName,
		eblPlatform: eblPlatform,
	}
}

// withIdentifyingCode adds an identifying code to the party.
func (b *RecipientPartyBuilder) WithIdentifyingCode(codeListProvider, partyCode string, codeListName *string) *RecipientPartyBuilder {
	b.identifyingCodes = append(b.identifyingCodes, IdentifyingCode{
		CodeListProvider: codeListProvider,
		CodeListName:     codeListName,
		PartyCode:        partyCode,
	})
	return b
}

// withTaxReference adds a tax and legal reference to the party.
func (b *RecipientPartyBuilder) WithTaxReference(t, countryCode, value string) *RecipientPartyBuilder {
	b.taxLegalReferences = append(b.taxLegalReferences, TaxLegalReference{
		Type:        t,
		CountryCode: countryCode,
		Value:       value,
	})
	return b
}

func (b *ActorPartyBuilder) WithRepresentedBy(partyName string, identifyingCode *IdentifyingCode) *ActorPartyBuilder {
	b.representedParty = &RepresentedActorParty{
		PartyName:        partyName,
		IdentifyingCodes: []IdentifyingCode{},
	}
	if identifyingCode != nil {
		b.representedParty.IdentifyingCodes = append(b.representedParty.IdentifyingCodes, *identifyingCode)
	}
	return b
}

func (b *ActorPartyBuilder) Build() (ActorParty, error) {
	actorParty := ActorParty{
		PartyName:          b.partyName,
		EblPlatform:        b.eblPlatform,
		IdentifyingCodes:   b.identifyingCodes,
		TaxLegalReferences: b.taxLegalReferences,
		RepresentedParty:   b.representedParty,
	}
	if err := actorParty.ValidateStructure(); err != nil {
		return ActorParty{}, err
	}
	return actorParty, nil
}

type ActorPartyBuilder struct {
	partyName          string
	eblPlatform        string
	identifyingCodes   []IdentifyingCode
	taxLegalReferences []TaxLegalReference
	representedParty   *RepresentedActorParty
}

func NewActorPartyBuilder(partyName, eblPlatform string) *ActorPartyBuilder {
	return &ActorPartyBuilder{
		partyName:   partyName,
		eblPlatform: eblPlatform,
	}
}

// withIdentifyingCode adds an identifying code to the party.
func (b *ActorPartyBuilder) WithIdentifyingCode(codeListProvider, partyCode string, codeListName *string) *ActorPartyBuilder {
	b.identifyingCodes = append(b.identifyingCodes, IdentifyingCode{
		CodeListProvider: codeListProvider,
		CodeListName:     codeListName,
		PartyCode:        partyCode,
	})
	return b
}

// withTaxReference adds a tax and legal reference to the party.
func (b *ActorPartyBuilder) WithTaxReference(t, countryCode, value string) *ActorPartyBuilder {
	b.taxLegalReferences = append(b.taxLegalReferences, TaxLegalReference{
		Type:        t,
		CountryCode: countryCode,
		Value:       value,
	})
	return b
}

func (b *RecipientPartyBuilder) WithRepresentedBy(partyName string, identifyingCode *IdentifyingCode) *RecipientPartyBuilder {
	b.representedParty = &RepresentedRecipientParty{
		PartyName:        partyName,
		IdentifyingCodes: []IdentifyingCode{},
	}
	if identifyingCode != nil {
		b.representedParty.IdentifyingCodes = append(b.representedParty.IdentifyingCodes, *identifyingCode)
	}
	return b
}

func (b *RecipientPartyBuilder) Build() (RecipientParty, error) {
	recipientParty := RecipientParty{
		PartyName:          b.partyName,
		EblPlatform:        b.eblPlatform,
		IdentifyingCodes:   b.identifyingCodes,
		TaxLegalReferences: b.taxLegalReferences,
		RepresentedParty:   b.representedParty,
	}
	if err := recipientParty.ValidateStructure(); err != nil {
		return RecipientParty{}, err
	}
	return recipientParty, nil
}

// TOD
type MatchStrategy int

const (
	// MatchAny requires at least one code to match (default).
	MatchAny MatchStrategy = iota
	// MatchAll requires all codes in the smaller set to match.
	MatchAll
)

// TODO review
// IdentifyingCodesMatch returns true if the two slices of IdentifyingCode satisfy
// the provided MatchStrategy.
func IdentifyingCodesMatch(a, b []IdentifyingCode, strategy MatchStrategy) bool {
	switch strategy {
	case MatchAll:
		smaller, larger := a, b
		if len(b) < len(a) {
			smaller, larger = b, a
		}
		for _, s := range smaller {
			found := false
			for _, l := range larger {
				if s.CodeListProvider == l.CodeListProvider && s.PartyCode == l.PartyCode {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default: // MatchAny
		for _, codeA := range a {
			for _, codeB := range b {
				if codeA.CodeListProvider == codeB.CodeListProvider && codeA.PartyCode == codeB.PartyCode {
					return true
				}
			}
		}
		return false
	}
}
