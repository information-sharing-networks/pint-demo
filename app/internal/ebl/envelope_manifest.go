package ebl

// envelope_manifest.go includes the builders for creating DCSA PINT API envelope manifests.

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// EnvelopeManifest is signed by the sender and provided in the transfer envelope,
// alongside the original eBL JSON and the full transfer chain.
//
// The signed manifest serves several purposes
//  1. The signature is used to confirm the manifest data is authentic (signed by the expected sender)
//  2. the manifest payload is used to confirm the eBL and transfer chain have not been tampered with.
//  3. Finally, if any supporting documents are required as part of the transfer, they will be sent separately -
//     the manifest includes metadata which is used by the receiver to confirm the documents have been transferred correctly.
type EnvelopeManifest struct {

	// TransportDocumentChecksum is the SHA-256 hash of the canonicalized eBL document (aka transport document).
	//
	// This should not change during the lifetime of the BL.
	TransportDocumentChecksum TransportDocumentChecksum `json:"transportDocumentChecksum"`

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 hash of the most recent entry
	// in the transfer chain.
	//
	// The transfer chain contains a history of transactions that have happened to the eBL.
	// Each group of transactions is signed by the platform that created it, and the next group in the chain includes
	// the checksum of the previous group as an anti-tampering measure.
	//
	// Including the checksum of the latest transfer chain entry in the manifest binds the manifest to the
	// specific transfer chain it was created for.
	LastEnvelopeTransferChainEntrySignedContentChecksum TransferChainEntrySignedContentChecksum `json:"lastEnvelopeTransferChainEntrySignedContentChecksum"`

	// EBLVisualisationByCarrier contains metadata for the eBL visualisation (optional).
	// The visualisation provides a human-readable version of the eBL, and can optionally be provided
	// by the carrier at the point they issue the eBL.
	//
	// If provided the metadata must be included in the manifst for all subsequent transfers so
	// that the downstream receivers can receive and verify the document.
	EBLVisualisationByCarrier *DocumentMetadata `json:"eBLVisualisationByCarrier,omitempty"`

	// SupportingDocuments contains metadata for supporting documents (optional).
	// this allows the sender to provide additional documents that are relevant to the eBL transfer
	// (commercial invoices, packing lists etc.)
	SupportingDocuments []DocumentMetadata `json:"supportingDocuments,omitempty"`
}

// EnvelopeManifestSignedContent: a JWS compact serialization of an EnvelopeManifest payload.
//
// This is created by the sending platform and included in the transfer envelope.
// the receiving platform verifies the signature and uses the decoded payload to verify the
// eBL and transfer chain have not been tampered with, and to learn of any
// supporting documents that need to be received.
type EnvelopeManifestSignedContent string

// Payload decodes the JWS and returns the EnvelopeManifest payload.
// Note this function does not verify the JWS signature.
func (e EnvelopeManifestSignedContent) Payload() (*EnvelopeManifest, error) {

	// extract the eBL visualization from the manifest
	// We don't verify the signature here because the envelope was already verified when received
	parts := strings.Split(string(e), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	manifestPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode manifest JWS payload %v", err)
	}

	var envelopeManifest EnvelopeManifest
	if err := json.Unmarshal(manifestPayload, &envelopeManifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal received envelope manifest: %v", err)
	}
	return &envelopeManifest, nil
}

func (e EnvelopeManifestSignedContent) Checksum() (string, error) {
	c, err := crypto.Hash([]byte(e))
	if err != nil {
		return "", fmt.Errorf("failed to crypto.Hash envelope manifest: %w", err)
	}
	return c, nil
}

// Header extracts the JWS header from the envelope manifest.
func (e EnvelopeManifestSignedContent) Header() (crypto.JWSHeader, error) {
	return crypto.ParseJWSHeader(string(e))
}

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification.
func (e *EnvelopeManifest) ValidateStructure() error {
	if e.TransportDocumentChecksum == "" {
		return NewEnvelopeError("transportDocumentChecksum is required")
	}
	if e.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
		return NewEnvelopeError("lastEnvelopeTransferChainEntrySignedContentChecksum is required")
	}
	if e.EBLVisualisationByCarrier != nil {
		if err := e.EBLVisualisationByCarrier.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, "eBLVisualisationByCarrier")
		}
	}
	for i, doc := range e.SupportingDocuments {
		if err := doc.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("supportingDocuments[%d]", i))
		}
	}
	return nil
}

// EnvelopeManifestBuilder helps build EnvelopeManifest for PINT transfers.
// The builder canonicalizes the transport document JSON, calculates the required checksums and validates the structure.
type EnvelopeManifestBuilder struct {

	// transportDocumentJSON is JCS-canonicalized JSON
	transportDocumentJSON []byte

	// lastEnvelopeTransferChainEntrySignedContent is the JWS compact serialization of the most recent EnvelopeTransferChainEntry
	lastEnvelopeTransferChainEntrySignedContent TransferChainEntrySignedContent

	// Optional: eBL visualisation metadata - contains the checksum of the decoded binary content
	eblVisualisationByCarrierContent *DocumentMetadata

	// Optional: supporting documents metadata - contains the checksum of the decoded binary content
	supportingDocuments []DocumentMetadata
}

// NewEnvelopeManifestBuilder creates a new builder for EnvelopeManifest.
//
// To build an envelope manifest:
//  1. Create an EnvelopeManifestBuilder
//  2. Add the required fields using the builder methods
//  3. Call Build() to create the EnvelopeManifest struct
//  4. Sign the manifest using Sign()
//  5. Add the signed manifest to the envelope transfer request
func NewEnvelopeManifestBuilder() *EnvelopeManifestBuilder {
	return &EnvelopeManifestBuilder{}
}

// WithTransportDocument sets the transport document (must be valid JSON).
func (e *EnvelopeManifestBuilder) WithTransportDocument(doc json.RawMessage) *EnvelopeManifestBuilder {
	e.transportDocumentJSON = doc
	return e
}

// WithLastTransferChainEntry sets the last transfer chain entry JWS.
func (e *EnvelopeManifestBuilder) WithLastTransferChainEntry(JwsToken TransferChainEntrySignedContent) *EnvelopeManifestBuilder {
	e.lastEnvelopeTransferChainEntrySignedContent = JwsToken
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

// Build creates the EnvelopeManifest with calculated checksums and optional document metadata.
func (e *EnvelopeManifestBuilder) Build() (*EnvelopeManifest, error) {
	// Validate required fields
	if e.transportDocumentJSON == nil {
		return nil, NewEnvelopeError("transport document is required")
	}

	if e.lastEnvelopeTransferChainEntrySignedContent == "" {
		return nil, NewEnvelopeError("last transfer chain entry is required")
	}

	transportDocumentChecksum, err := TransportDocument(e.transportDocumentJSON).Checksum()
	if err != nil {
		return nil, WrapInternalError(err, "failed to calculate transport document checksum")
	}

	// Calculate the checksum of the last envelope transfer chain entry
	lastTransferChainChecksum, err := crypto.Hash([]byte(e.lastEnvelopeTransferChainEntrySignedContent))
	if err != nil {
		return nil, WrapInternalError(err, "failed to crypto.Hash last transfer chain entry")
	}

	// Create EnvelopeManifest
	manifest := &EnvelopeManifest{
		TransportDocumentChecksum:                           TransportDocumentChecksum(transportDocumentChecksum),
		LastEnvelopeTransferChainEntrySignedContentChecksum: TransferChainEntrySignedContentChecksum(lastTransferChainChecksum),
	}

	// Add eBL visualisation metadata (optional)
	if e.eblVisualisationByCarrierContent != nil {
		if err := e.eblVisualisationByCarrierContent.ValidateStructure(); err != nil {
			return nil, WrapEnvelopeError(err, "eBL visualisation")
		}
		manifest.EBLVisualisationByCarrier = e.eblVisualisationByCarrierContent
	}

	// Add supporting documents metadata (optional)
	if len(e.supportingDocuments) > 0 {
		for i, doc := range e.supportingDocuments {
			if err := doc.ValidateStructure(); err != nil {
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
// Returns a JWS compact serialization string ready to include in Envelope.envelopeManifestSignedContent.
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
