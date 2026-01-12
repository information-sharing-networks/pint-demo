// envelope.go implements the DCSA EBL_PINT v3.0.0 specification for creating and signing envelope manifests.
//
// PINT Transfer Flow:
// i)   Generate canonical JSON for transport document
// ii)  Calculate SHA-256 checksums (transport document + last transfer chain entry)
// iii) Decode eBL visualisation (if provided) from Base64 to binary, calculate checksum and include in eblVisualisationByCarrier DocumentMetadata
// iv)  Decode supporting documents (if provided) from Base64 to binary, calculate checksums and include in supportingDocuments DocumentMetadata array
// v)   Create EnvelopeManifest with checksums (transportDocument, lastTransferChainEntry) and document metadata (eblVisualisationByCarrier, supportingDocuments)
// vi)  Sign the canonical EnvelopeManifest to create JWS
// vii) Include JWS in EblEnvelope.envelopeManifestSignedContent

package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
)

// EnvelopeManifest is used to verify the transport document and the transfer chain have not been tampered with
// and to provide details of any supporting documents transferred via PINT.
// this is the payload that gets signed and included in eblEnvelope.envelopeManifestSignedContent
type EnvelopeManifest struct {

	// TransportDocumentChecksum is the SHA-256 hash of the canonicalized transport document.
	// This is calculated over the canonicalized JSON bytes of the transport document and should never change during the lifetime of the BL.
	TransportDocumentChecksum string `json:"transportDocumentChecksum"`

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 hash of the most recent entry
	// in the transfer chain.
	// This allows the receiving platform to verify that the envelope manifest was created by the
	// sending platform specifically for this transfer, preventing replay attacks
	LastEnvelopeTransferChainEntrySignedContentChecksum string `json:"lastEnvelopeTransferChainEntrySignedContentChecksum"`

	// EBLVisualisationByCarrier contains metadata for the eBL visualisation (optional).
	EBLVisualisationByCarrier *DocumentMetadata `json:"eBLVisualisationByCarrier,omitempty"`

	// SupportingDocuments contains metadata for supporting documents (optional).
	SupportingDocuments []DocumentMetadata `json:"supportingDocuments,omitempty"`
}

// EnvelopeManifestSignedContent represents a JWS compact serialization of an EnvelopeManifest.
type EnvelopeManifestSignedContent string

// EnvelopeTransferChainEntrySignedContent represents a JWS compact serialization of an EnvelopeTransferChainEntry.
type EnvelopeTransferChainEntrySignedContent string

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (e *EnvelopeManifest) Validate() error {
	if e.TransportDocumentChecksum == "" {
		return fmt.Errorf("transportDocumentChecksum is required")
	}
	if e.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
		return fmt.Errorf("lastEnvelopeTransferChainEntrySignedContentChecksum is required")
	}
	if e.EBLVisualisationByCarrier != nil {
		if err := e.EBLVisualisationByCarrier.Validate(); err != nil {
			return fmt.Errorf("eBLVisualisationByCarrier: %w", err)
		}
	}
	for i, doc := range e.SupportingDocuments {
		if err := doc.Validate(); err != nil {
			return fmt.Errorf("supportingDocuments[%d]: %w", i, err)
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
func (b *EnvelopeManifestBuilder) WithTransportDocument(transportDocumentJSON []byte) *EnvelopeManifestBuilder {
	b.transportDocumentJSON = transportDocumentJSON
	return b
}

// WithLastTransferChainEntry sets the last transfer chain entry JWS
func (b *EnvelopeManifestBuilder) WithLastTransferChainEntry(jwsString EnvelopeTransferChainEntrySignedContent) *EnvelopeManifestBuilder {
	b.lastEnvelopeTransferChainEntrySignedContent = jwsString
	return b
}

// WithEBLVisualisationByCarrier sets the eBL visualisation content.
//
// Expects a DocumentMetadata struct representing the eBL visualisation.
func (b *EnvelopeManifestBuilder) WithEBLVisualisationByCarrier(docMeta DocumentMetadata) *EnvelopeManifestBuilder {
	b.eblVisualisationByCarrierContent = &docMeta
	return b
}

// WithSupportingDocuments sets the supporting documents for the envelope transfer.
//
// Expects a slice of DocumentMetadata structs representing supporting documents.
func (b *EnvelopeManifestBuilder) WithSupportingDocuments(docs []DocumentMetadata) *EnvelopeManifestBuilder {
	b.supportingDocuments = docs
	return b
}

// Build creates the EnvelopeManifest with calculated checksums and optional document metadata
func (b *EnvelopeManifestBuilder) Build() (*EnvelopeManifest, error) {
	// Validate required fields
	if len(b.transportDocumentJSON) == 0 {
		return nil, fmt.Errorf("transport document is required")
	}

	if b.lastEnvelopeTransferChainEntrySignedContent == "" {
		return nil, fmt.Errorf("last transfer chain entry is required")
	}

	// Canonicalize transport document
	canonicalDocument, err := CanonicalizeJSON(b.transportDocumentJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize transport document: %w", err)
	}

	// Calculate checksums
	transportDocumentChecksum, err := Hash(canonicalDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to hash transport document: %w", err)
	}

	// calculate the checksum of the last enevelope transfer chain entry
	lastTransferChainChecksum, err := Hash([]byte(b.lastEnvelopeTransferChainEntrySignedContent))
	if err != nil {
		return nil, fmt.Errorf("failed to hash last transfer chain entry: %w", err)
	}

	// Create EnvelopeManifest
	manifest := &EnvelopeManifest{
		TransportDocumentChecksum:                           transportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: lastTransferChainChecksum,
	}

	// add eBL visualisation metadata (optional)
	if b.eblVisualisationByCarrierContent != nil {
		if err := b.eblVisualisationByCarrierContent.Validate(); err != nil {
			return nil, fmt.Errorf("eBL visualisation: %w", err)
		}
		manifest.EBLVisualisationByCarrier = b.eblVisualisationByCarrierContent
	}

	// add supporting documents metadata (optional)
	if len(b.supportingDocuments) > 0 {
		for i, doc := range b.supportingDocuments {
			if err := doc.Validate(); err != nil {
				return nil, fmt.Errorf("supporting document %d: %w", i, err)
			}
		}
		manifest.SupportingDocuments = b.supportingDocuments
	}

	return manifest, nil
}

// SignWithEd25519AndX5C creates the envelopeManifestSignedContent JWS string with x5c headers using Ed25519
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithEd25519AndX5C(privateKey ed25519.PrivateKey, keyID string, certChain []*x509.Certificate) (EnvelopeManifestSignedContent, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope manifest: %w", err)

	}

	// Sign (Canonicalization happens in SignJSONWithEd25519AndX5C)
	jws, err := SignJSONWithEd25519AndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return EnvelopeManifestSignedContent(jws), nil
}

// SignWithEd25519 creates the envelopeManifestSignedContent JWS string using Ed25519 (no x5c header)
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithEd25519(privateKey ed25519.PrivateKey, keyID string) (EnvelopeManifestSignedContent, error) {

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope manifest: %w", err)

	}

	// canonicalize the JSON
	canonicalJSON, err := CanonicalizeJSON(jsonBytes)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize envelope manifest: %w", err)
	}

	jws, err := SignJSONWithEd25519(canonicalJSON, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return EnvelopeManifestSignedContent(jws), nil
}

// SignWithRSAAndX5C creates the envelopeManifestSignedContent JWS string with x5c headers using RSA
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithRSAAndX5C(privateKey *rsa.PrivateKey, keyID string, certChain []*x509.Certificate) (EnvelopeManifestSignedContent, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope manifest: %w", err)

	}

	// Sign (Canonicalization happens in SignJSONWithRSAAndX5C)
	jws, err := SignJSONWithRSAAndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return EnvelopeManifestSignedContent(jws), nil
}

// SignWithRSA creates the envelopeManifestSignedContent JWS string using RSA (no x5c header)
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithRSA(privateKey *rsa.PrivateKey, keyID string) (EnvelopeManifestSignedContent, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope manifest: %w", err)

	}

	// Sign (Canonicalization happens in SignJSONWithRSA)
	jws, err := SignJSONWithRSA(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return EnvelopeManifestSignedContent(jws), nil
}

// EblEnvelope represents the complete DCSA PINT envelope containing the transport document,
// the signed envelope manifest, and the full transfer chain.
//
// This is the top-level structure that gets transferred between eBL platforms.
type EblEnvelope struct {

	// TransportDocument: The transport document (Bill of Lading) as a JSON object.
	TransportDocument []byte `json:"transportDocument"`

	// EnvelopeManifestSignedContent: JWS compact serialization of the EnvelopeManifest.
	// This is signed by the sending platform and contains checksums to verify integrity.
	EnvelopeManifestSignedContent EnvelopeManifestSignedContent `json:"envelopeManifestSignedContent"`

	// EnvelopeTransferChain: Ordered list of JWS strings representing the complete transfer chain.
	// Each entry is a signed EnvelopeTransferChainEntry. The full chain is required to verify
	// the complete history and detect tampering or double-spending.
	EnvelopeTransferChain []EnvelopeTransferChainEntrySignedContent `json:"envelopeTransferChain"`
}

// Validate checks that all required fields are present per DCSA EBL_PINT specification
func (e *EblEnvelope) Validate() error {
	if len(e.TransportDocument) == 0 {
		return fmt.Errorf("transportDocument is required")
	}
	if e.EnvelopeManifestSignedContent == "" {
		return fmt.Errorf("envelopeManifestSignedContent is required")
	}
	if len(e.EnvelopeTransferChain) == 0 {
		return fmt.Errorf("envelopeTransferChain must contain at least one entry")
	}
	// Validate that transportDocument is valid JSON
	if !json.Valid(e.TransportDocument) {
		return fmt.Errorf("transportDocument must be valid JSON")
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
func (b *EblEnvelopeBuilder) WithTransportDocument(transportDocumentJSON []byte) *EblEnvelopeBuilder {
	b.transportDocument = transportDocumentJSON
	return b
}

// WithEnvelopeManifestSignedContent sets the signed envelope manifest JWS
func (b *EblEnvelopeBuilder) WithEnvelopeManifestSignedContent(jws EnvelopeManifestSignedContent) *EblEnvelopeBuilder {
	b.envelopeManifestSignedContent = jws
	return b
}

// WithEnvelopeTransferChain sets the complete transfer chain (array of JWS strings)
func (b *EblEnvelopeBuilder) WithEnvelopeTransferChain(chain []EnvelopeTransferChainEntrySignedContent) *EblEnvelopeBuilder {
	b.envelopeTransferChain = chain
	return b
}

// AddTransferChainEntry appends a single transfer chain entry JWS to the chain
func (b *EblEnvelopeBuilder) AddTransferChainEntry(jws EnvelopeTransferChainEntrySignedContent) *EblEnvelopeBuilder {
	b.envelopeTransferChain = append(b.envelopeTransferChain, jws)
	return b
}

// Build creates the EblEnvelope
func (b *EblEnvelopeBuilder) Build() (*EblEnvelope, error) {
	envelope := &EblEnvelope{
		TransportDocument:             b.transportDocument,
		EnvelopeManifestSignedContent: b.envelopeManifestSignedContent,
		EnvelopeTransferChain:         b.envelopeTransferChain,
	}

	if err := envelope.Validate(); err != nil {
		return nil, fmt.Errorf("invalid envelope: %w", err)
	}

	return envelope, nil
}
