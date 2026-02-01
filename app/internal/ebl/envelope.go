package ebl

// envelope.go implements the DCSA EBL_PINT v3.0.0 specification for creating and signing ebl Envelopes
//
// PINT Transfer Flow:
// i)   Generate canonical JSON for transport document
// ii)  Calculate SHA-256 checksums (transport document + last transfer chain entry)
// iii) Decode eBL visualisation (if provided) from Base64 to binary, calculate checksum and include in eblVisualisationByCarrier DocumentMetadata
// iv)  Decode supporting documents (if provided) from Base64 to binary, calculate checksums and include in supportingDocuments DocumentMetadata array
// v)   Create EnvelopeManifest with checksums (transportDocument, lastTransferChainEntry) and document metadata (eblVisualisationByCarrier, supportingDocuments)
// vi)  Sign the canonical EnvelopeManifest to create JWS
// vii) Include JWS in EblEnvelope.envelopeManifestSignedContent

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// EblEnvelope represents the complete DCSA PINT envelope containing the transport document,
// the signed envelope manifest, and the full transfer chain.
//
// This is the top-level structure that gets transferred between eBL platforms.
type EblEnvelope struct {

	// TransportDocument: The transport document (Bill of Lading) as a JSON object.
	TransportDocument json.RawMessage `json:"transportDocument" swaggertype:"object"`

	// EnvelopeManifestSignedContent: JWS compact serialization of the EnvelopeManifest
	// (signed by the sending platform).
	//
	// The EnvelopeManifest payload is used by the receiver to verify that the transport
	// document and the transfer chain have not been tampered with and to establish details
	// of any supporting documents that will be subsequently transferred by the sender.
	EnvelopeManifestSignedContent EnvelopeManifestSignedContent `json:"envelopeManifestSignedContent"`

	// EnvelopeTransferChain: Ordered list of JWS tokens representing the complete
	// transfer chain.
	//
	// Each EnvelopeTransferChainEntry represents a batch of transactions
	// that happened on a single platform and is is signed by the sending platform.
	//
	// The full chain is required by the receiver to verify the complete history and detect tampering.
	EnvelopeTransferChain []EnvelopeTransferChainEntrySignedContent `json:"envelopeTransferChain"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (e *EblEnvelope) Validate() error {
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

// EblEnvelopeBuilder helps build EblEnvelope for PINT transfers
type EblEnvelopeBuilder struct {
	transportDocument             []byte
	envelopeManifestSignedContent EnvelopeManifestSignedContent
	envelopeTransferChain         []EnvelopeTransferChainEntrySignedContent
}

// NewEblEnvelopeBuilder creates a new builder for EblEnvelope
func NewEblEnvelopeBuilder() *EblEnvelopeBuilder {
	return &EblEnvelopeBuilder{
		envelopeTransferChain: make([]EnvelopeTransferChainEntrySignedContent, 0),
	}
}

// WithTransportDocument sets the transport document (must be valid JSON)
func (e *EblEnvelopeBuilder) WithTransportDocument(transportDocumentJSON []byte) *EblEnvelopeBuilder {
	e.transportDocument = transportDocumentJSON
	return e
}

// WithEnvelopeManifestSignedContent sets the signed envelope manifest JWS
func (e *EblEnvelopeBuilder) WithEnvelopeManifestSignedContent(jws EnvelopeManifestSignedContent) *EblEnvelopeBuilder {
	e.envelopeManifestSignedContent = jws
	return e
}

// WithEnvelopeTransferChain sets the complete transfer chain (array of JWS strings)
func (e *EblEnvelopeBuilder) WithEnvelopeTransferChain(chain []EnvelopeTransferChainEntrySignedContent) *EblEnvelopeBuilder {
	e.envelopeTransferChain = chain
	return e
}

// AddTransferChainEntry appends a single transfer chain entry JWS to the chain
func (e *EblEnvelopeBuilder) AddTransferChainEntry(jws EnvelopeTransferChainEntrySignedContent) *EblEnvelopeBuilder {
	e.envelopeTransferChain = append(e.envelopeTransferChain, jws)
	return e
}

// Build creates the EblEnvelope
func (e *EblEnvelopeBuilder) Build() (*EblEnvelope, error) {
	envelope := &EblEnvelope{
		TransportDocument:             e.transportDocument,
		EnvelopeManifestSignedContent: e.envelopeManifestSignedContent,
		EnvelopeTransferChain:         e.envelopeTransferChain,
	}

	if err := envelope.Validate(); err != nil {
		return nil, WrapEnvelopeError(err, "invalid envelope")
	}

	return envelope, nil
}

// EnvelopeManifest is used to verify the transport document and the transfer chain have not been tampered with
// and to provide details of any supporting documents transferred via PINT.
// this is the payload that gets signed and included in eblEnvelope.envelopeManifestSignedContent
type EnvelopeManifest struct {

	// TransportDocumentChecksum is the SHA-256 crypto.Hash of the canonicalized transport document.
	// This is calculated over the canonicalized JSON bytes of the transport document and should never change during the lifetime of the BL.
	TransportDocumentChecksum string `json:"transportDocumentChecksum"`

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 crypto.Hash of the most recent entry
	// in the transfer chain.
	// This binds the manifest to the specific transfer chain it was created for,
	// preventing an attacker from replacing the last entry with a valid one from a different transfer.
	LastEnvelopeTransferChainEntrySignedContentChecksum string `json:"lastEnvelopeTransferChainEntrySignedContentChecksum"`

	// EBLVisualisationByCarrier contains metadata for the eBL visualisation (optional).
	EBLVisualisationByCarrier *DocumentMetadata `json:"eBLVisualisationByCarrier,omitempty"`

	// SupportingDocuments contains metadata for supporting documents (optional).
	SupportingDocuments []DocumentMetadata `json:"supportingDocuments,omitempty"`
}

// EnvelopeManifestSignedContent: a JWS compact serialization of an EnvelopeManifest payload.
//
// This is created by the sending platform and included in eblEnvelope.envelopeManifestSignedContent.
// The receiving platform uses this to verify the manifest has not been tampered with.
type EnvelopeManifestSignedContent string

// EnvelopeTransferChainEntrySignedContent represents a JWS compact serialization of an EnvelopeTransferChainEntry.
//
// An array of all the signed transfer chain entries is included in eblEnvelope.envelopeTransferChain and
// represents the activity that has happened to the eBL prior to this transfer.
type EnvelopeTransferChainEntrySignedContent string

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (e *EnvelopeManifest) Validate() error {
	if e.TransportDocumentChecksum == "" {
		return NewEnvelopeError("transportDocumentChecksum is required")
	}
	if e.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
		return NewEnvelopeError("lastEnvelopeTransferChainEntrySignedContentChecksum is required")
	}
	if e.EBLVisualisationByCarrier != nil {
		if err := e.EBLVisualisationByCarrier.Validate(); err != nil {
			return WrapEnvelopeError(err, "eBLVisualisationByCarrier")
		}
	}
	for i, doc := range e.SupportingDocuments {
		if err := doc.Validate(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("supportingDocuments[%d]", i))
		}
	}
	return nil
}

// EnvelopeManifestBuilder helps build EnvelopeManifest for PINT transfers
type EnvelopeManifestBuilder struct {

	// transportDocumentJSON is the raw JSON bytes of the transport document.
	transportDocumentJSON []byte

	// lastEnvelopeTransferChainEntrySignedContent is the JWS compact serialization of the most recent EnvelopeTransferChainEntry
	lastEnvelopeTransferChainEntrySignedContent EnvelopeTransferChainEntrySignedContent

	// Optional: eBL visualisation metadata - contains the checksum of the decoded binary content
	eblVisualisationByCarrierContent *DocumentMetadata

	// Optional: supporting documents metadata - contains the checksum of the decoded binary content
	supportingDocuments []DocumentMetadata
}

// DocumentMetadata represents documents transferred via PINT and contains the document's checksum and other metadata
// The document's binary content is not included in this structure and is sent separately.
type DocumentMetadata struct {

	// name: The name of the document
	Name string `json:"name"`

	// size: The size of the decoded document in bytes (not the Base64 encoded size)
	Size int64 `json:"size"`

	// mediaType: MIME type of the document
	MediaType string `json:"mediaType"`

	// documentChecksum: SHA-256 checksum of the document
	DocumentChecksum string `json:"documentChecksum"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (d *DocumentMetadata) Validate() error {
	if d.Name == "" {
		return fmt.Errorf("name is required")
	}
	if d.Size <= 0 {
		return fmt.Errorf("size must be greater than 0")
	}
	if d.MediaType == "" {
		return fmt.Errorf("mediaType is required")
	}
	if d.DocumentChecksum == "" {
		return fmt.Errorf("documentChecksum is required")
	}
	return nil
}

// NewEnvelopeManifestBuilder creates a new builder for EnvelopeManifest
func NewEnvelopeManifestBuilder() *EnvelopeManifestBuilder {
	return &EnvelopeManifestBuilder{}
}

// WithTransportDocument sets the transport document (must be valid JSON)
func (e *EnvelopeManifestBuilder) WithTransportDocument(transportDocumentJSON []byte) *EnvelopeManifestBuilder {
	e.transportDocumentJSON = transportDocumentJSON
	return e
}

// WithLastTransferChainEntry sets the last transfer chain entry JWS
func (e *EnvelopeManifestBuilder) WithLastTransferChainEntry(jwsString EnvelopeTransferChainEntrySignedContent) *EnvelopeManifestBuilder {
	e.lastEnvelopeTransferChainEntrySignedContent = jwsString
	return e
}

// WithEBLVisualisationByCarrier sets the eBL visualisation content.
//
// Expects a DocumentMetadata struct representing the eBL visualisation.
func (e *EnvelopeManifestBuilder) WithEBLVisualisationByCarrier(docMeta DocumentMetadata) *EnvelopeManifestBuilder {
	e.eblVisualisationByCarrierContent = &docMeta
	return e
}

// WithSupportingDocuments sets the supporting documents for the envelope transfer.
//
// Expects a slice of DocumentMetadata structs representing supporting documents.
func (e *EnvelopeManifestBuilder) WithSupportingDocuments(docs []DocumentMetadata) *EnvelopeManifestBuilder {
	e.supportingDocuments = docs
	return e
}

// Build creates the EnvelopeManifest with calculated checksums and optional document metadata
func (e *EnvelopeManifestBuilder) Build() (*EnvelopeManifest, error) {
	// Validate required fields
	if len(e.transportDocumentJSON) == 0 {
		return nil, NewEnvelopeError("transport document is required")
	}

	if e.lastEnvelopeTransferChainEntrySignedContent == "" {
		return nil, NewEnvelopeError("last transfer chain entry is required")
	}

	// Canonicalize transport document
	canonicalDocument, err := crypto.CanonicalizeJSON(e.transportDocumentJSON)
	if err != nil {
		return nil, WrapInternalError(err, "failed to canonicalize transport document")
	}

	// Calculate checksums
	transportDocumentChecksum, err := crypto.Hash(canonicalDocument)
	if err != nil {
		return nil, WrapInternalError(err, "failed to crypto.Hash transport document")
	}

	// calculate the checksum of the last enevelope transfer chain entry
	lastTransferChainChecksum, err := crypto.Hash([]byte(e.lastEnvelopeTransferChainEntrySignedContent))
	if err != nil {
		return nil, WrapInternalError(err, "failed to crypto.Hash last transfer chain entry")
	}

	// Create EnvelopeManifest
	manifest := &EnvelopeManifest{
		TransportDocumentChecksum:                           transportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: lastTransferChainChecksum,
	}

	// add eBL visualisation metadata (optional)
	if e.eblVisualisationByCarrierContent != nil {
		if err := e.eblVisualisationByCarrierContent.Validate(); err != nil {
			return nil, WrapEnvelopeError(err, "eBL visualisation")
		}
		manifest.EBLVisualisationByCarrier = e.eblVisualisationByCarrierContent
	}

	// add supporting documents metadata (optional)
	if len(e.supportingDocuments) > 0 {
		for i, doc := range e.supportingDocuments {
			if err := doc.Validate(); err != nil {
				return nil, WrapEnvelopeError(err, fmt.Sprintf("supporting document %d", i))
			}
		}
		manifest.SupportingDocuments = e.supportingDocuments
	}

	return manifest, nil
}

// Sign creates the envelopeManifestSignedContent JWS string.
//
// The privateKey can be either ed25519.PrivateKey or *rsa.PrivateKey.
// If certChain is provided, the x5c header will be included in the JWS for non-repudiation.
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (e *EnvelopeManifest) Sign(privateKey any, certChain []*x509.Certificate) (EnvelopeManifestSignedContent, error) {
	// Marshal to JSON
	jsonBytes, err := json.Marshal(e)
	if err != nil {
		return "", WrapInternalError(err, "failed to marshal envelope manifest")
	}

	// Sign
	jws, err := crypto.SignJSON(jsonBytes, privateKey, certChain)
	if err != nil {
		return "", WrapSignatureError(err, "failed to sign manifest")
	}

	return EnvelopeManifestSignedContent(jws), nil
}
