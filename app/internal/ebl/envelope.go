package ebl

// envelope.go includes the builders for creating DCSA PINT API envelopes.
//

import (
	"encoding/json"
)

// Envelope represents the complete DCSA PINT envelope containing the transport document,
// the signed envelope manifest, and the full transfer chain.
//
// This is the top-level structure that gets transferred between eBL platforms.
type Envelope struct {

	// TransportDocument: The transport document (Bill of Lading) as a JSON object.
	TransportDocument json.RawMessage `json:"transportDocument" swaggertype:"object"`

	// Signed manifest covering the transport document, transfer chain and supporting documents
	// Use the EnvelopeManifestBuilder to create the manifest and sign it.
	EnvelopeManifestSignedContent EnvelopeManifestSignedContent `json:"envelopeManifestSignedContent"`

	// EnvelopeTransferChain: Ordered list of JWS tokens representing the complete
	// transfer chain.
	//
	// Each EnvelopeTransferChainEntry represents a batch of transactions
	// that happened on a single platform and is signed by the sending platform.
	//
	// The full chain is required by the receiver to verify the complete history and detect tampering.
	//
	// Use the EnvelopeTransferChainEntryBuilder to create the transfer chain entries and sign them.
	EnvelopeTransferChain []TransferChainEntrySignedContent `json:"envelopeTransferChain"`
}

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification.
func (e *Envelope) ValidateStructure() error {
	if len(e.TransportDocument) == 0 {
		return NewEnvelopeError("transportDocument is required")
	}
	if e.EnvelopeManifestSignedContent == "" {
		return NewEnvelopeError("envelopeManifestSignedContent is required")
	}
	if len(e.EnvelopeTransferChain) == 0 {
		return NewEnvelopeError("envelopeTransferChain must contain at least one entry")
	}
	// Validate that transportDocument is valid JSON
	if !json.Valid(e.TransportDocument) {
		return NewEnvelopeError("transportDocument must be valid JSON")
	}
	return nil
}

// EnvelopeBuilder helps build Envelope for PINT transfers.
type EnvelopeBuilder struct {
	transportDocument             []byte
	envelopeManifestSignedContent EnvelopeManifestSignedContent
	envelopeTransferChain         []TransferChainEntrySignedContent
}

// NewEnvelopeBuilder creates a new builder for Envelope.
func NewEnvelopeBuilder() *EnvelopeBuilder {
	return &EnvelopeBuilder{
		envelopeTransferChain: make([]TransferChainEntrySignedContent, 0),
	}
}

// WithTransportDocument sets the transport document (must be valid JSON).
func (e *EnvelopeBuilder) WithTransportDocument(transportDocumentJSON []byte) *EnvelopeBuilder {
	e.transportDocument = transportDocumentJSON
	return e
}

// WithEnvelopeManifestSignedContent sets the signed envelope manifest JWS.
func (e *EnvelopeBuilder) WithEnvelopeManifestSignedContent(jws EnvelopeManifestSignedContent) *EnvelopeBuilder {
	e.envelopeManifestSignedContent = jws
	return e
}

// WithEnvelopeTransferChain sets the complete transfer chain (array of JWS strings).
func (e *EnvelopeBuilder) WithEnvelopeTransferChain(chain []TransferChainEntrySignedContent) *EnvelopeBuilder {
	e.envelopeTransferChain = chain
	return e
}

// AddTransferChainEntry appends a single transfer chain entry JWS to the chain.
func (e *EnvelopeBuilder) AddTransferChainEntry(jws TransferChainEntrySignedContent) *EnvelopeBuilder {
	e.envelopeTransferChain = append(e.envelopeTransferChain, jws)
	return e
}

// Build creates the Envelope.
func (e *EnvelopeBuilder) Build() (*Envelope, error) {
	envelope := &Envelope{
		TransportDocument:             e.transportDocument,
		EnvelopeManifestSignedContent: e.envelopeManifestSignedContent,
		EnvelopeTransferChain:         e.envelopeTransferChain,
	}

	if err := envelope.ValidateStructure(); err != nil {
		return nil, WrapEnvelopeError(err, "invalid envelope")
	}

	return envelope, nil
}
