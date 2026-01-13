// issuance.go implements the DCSA EBL_ISS specification for creating and signing issuance manifests.
//
// Issuance Flow (this is the carrier's responsibility)
// i)   Generate canonical JSON for document and issueTo
// ii)  Calculate SHA-256 checksums (document + issueTo)
// iii) Decode eBL visualisation (if provided) from Base64 to binary and calculate checksum
// iv)  Create IssuanceManifest with checksums (document, issueTo, eblVisualisationByCarrier)
// v)   Sign the canonical IssuanceManifest to create JWS
// vi)  Include JWS in IssuanceRequest.issuanceManifestSignedContent

package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
)

// IssuanceManifest represents the DCSA IssuanceManifest structure
// This is the payload that gets signed in issuanceManifestSignedContent
type IssuanceManifest struct {

	//documentChecksum: SHA-256 of canonicalized transport document
	DocumentChecksum string `json:"documentChecksum"`

	// issueToChecksum: SHA-256 of canonicalized issueTo party
	IssueToChecksum string `json:"issueToChecksum"`

	// eBLVisualisationByCarrierChecksum: SHA-256 of decoded visualisation content (optional)
	EBLVisualisationByCarrierChecksum *string `json:"eBLVisualisationByCarrierChecksum,omitempty"`
}

// IssuanceManifestSignedContent represents a JWS compact serialization of an IssuanceManifest.
type IssuanceManifestSignedContent string

// Validate checks that all required fields are present per DCSA EBL_ISS specification
func (i *IssuanceManifest) Validate() error {
	if i.DocumentChecksum == "" {
		return fmt.Errorf("documentChecksum is required")
	}
	if i.IssueToChecksum == "" {
		return fmt.Errorf("issueToChecksum is required")
	}
	return nil
}

// IssuanceManifestBuilder is used to build IssuanceManifest with DCSA-compliant checksums
type IssuanceManifestBuilder struct {

	// documentJSON: JSON bytes of the transport document
	documentJSON []byte

	// issueToJSON: JSON bytes of the issueTo party
	issueToJSON []byte

	// eblVisualisationByCarrier: eBL visualisation metadata
	eBLVisualisationByCarrier *EBLVisualisationByCarrier
}

// EBLVisualisationByCarrier represents the eBL visualisation document.
// (optionally, the carrier can provide a human-readable visualisation of the eBL for the end user)
type EBLVisualisationByCarrier struct {

	// name: The name of the visualisation file
	Name string `json:"name"`

	// content: Base64-encoded binary content of the human readable visualisation (e.g a PDF)
	Content string `json:"content"`

	// contentType: The Media Type (MIME type) of the content
	ContentType string `json:"contentType"`
}

// Validate checks that all required fields are present per DCSA EBL_ISS specification
func (e *EBLVisualisationByCarrier) Validate() error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	if e.Content == "" {
		return fmt.Errorf("content is required")
	}
	if e.ContentType == "" {
		return fmt.Errorf("contentType is required")
	}
	return nil
}

// NewIssuanceManifestBuilder creates a new builder for IssuanceManifest
func NewIssuanceManifestBuilder() *IssuanceManifestBuilder {
	return &IssuanceManifestBuilder{}
}

// WithDocument sets the transport document (must be valid JSON)
// The document will be canonicalized by the Build() method before checksum calculation
func (b *IssuanceManifestBuilder) WithDocument(documentJSON []byte) *IssuanceManifestBuilder {
	b.documentJSON = documentJSON
	return b
}

// WithIssueTo sets the issueTo party (must be valid JSON)
// The issueTo will be canonicalized by the Build() method before checksum calculation
func (b *IssuanceManifestBuilder) WithIssueTo(issueToJSON []byte) *IssuanceManifestBuilder {
	b.issueToJSON = issueToJSON
	return b
}

// WithEBLVisualisation sets the eBL visualisation content.
//
// Expects the base64-encoded string from eblVisualisationByCarrier.content field in the JSON.
// The content will be decoded before calculating the checksum - Build() will return an error if the content is not valid base64.
func (b *IssuanceManifestBuilder) WithEBLVisualisation(EBLVisualisationByCarrier *EBLVisualisationByCarrier) *IssuanceManifestBuilder {
	b.eBLVisualisationByCarrier = EBLVisualisationByCarrier
	return b
}

func (b *IssuanceManifestBuilder) Build() (*IssuanceManifest, error) {

	// Validate required fields
	if len(b.documentJSON) == 0 {
		return nil, fmt.Errorf("document is required")
	}
	if len(b.issueToJSON) == 0 {
		return nil, fmt.Errorf("issueTo is required")
	}

	// Canonicalize JSON documents
	canonicalDocument, err := CanonicalizeJSON(b.documentJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize document: %w", err)
	}

	canonicalIssueTo, err := CanonicalizeJSON(b.issueToJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize issueTo: %w", err)
	}

	// Calculate SHA-256 checksums
	documentChecksum, err := Hash(canonicalDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to hash document: %w", err)
	}
	issueToChecksum, err := Hash(canonicalIssueTo)
	if err != nil {
		return nil, fmt.Errorf("failed to hash issueTo: %w", err)
	}

	// Create IssuanceManifest
	issuanceManifest := &IssuanceManifest{
		DocumentChecksum: documentChecksum,
		IssueToChecksum:  issueToChecksum,
	}

	// add eBL visualisation checksum (optional)
	if b.eBLVisualisationByCarrier != nil {
		if err := b.eBLVisualisationByCarrier.Validate(); err != nil {
			return nil, fmt.Errorf("eBLVisualisationByCarrier: %w", err)
		}

		// TODO validate mime type?
		// TODO check mime type is consistent with binary content?

		visualisationChecksum, err := HashFromBase64(
			b.eBLVisualisationByCarrier.Content,
			MaxDocumentSize,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to hash eBL visualisation: %w", err)
		}
		issuanceManifest.EBLVisualisationByCarrierChecksum = &visualisationChecksum
	}

	return issuanceManifest, nil
}

// SignWithEd25519AndX5C creates the issuanceManifestSignedContent JWS string using Ed25519
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithEd25519AndX5C(privateKey ed25519.PrivateKey, keyID string, certChain []*x509.Certificate) (IssuanceManifestSignedContent, error) {

	// serialize to JSON
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithEd25519AndX5C)
	jws, err := SignJSONWithEd25519AndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return IssuanceManifestSignedContent(jws), nil
}

// SignWithEd25519 creates the issuanceManifestSignedContent JWS string using Ed25519 (no x5c header)
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithEd25519(privateKey ed25519.PrivateKey, keyID string) (IssuanceManifestSignedContent, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithEd25519)
	jws, err := SignJSONWithEd25519(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return IssuanceManifestSignedContent(jws), nil
}

// SignWithRSAAndX5C creates the issuanceManifestSignedContent JWS string using RSA
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithRSAAndX5C(privateKey *rsa.PrivateKey, keyID string, certChain []*x509.Certificate) (IssuanceManifestSignedContent, error) {

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithRSAAndX5C)
	jws, err := SignJSONWithRSAAndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return IssuanceManifestSignedContent(jws), nil
}

// SignWithRSA creates the issuanceManifestSignedContent JWS string using RSA (no x5c header)
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithRSA(privateKey *rsa.PrivateKey, keyID string) (IssuanceManifestSignedContent, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}

	// Sign (Canonicalization happens in SignJSONWithRSA)
	jws, err := SignJSONWithRSA(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return IssuanceManifestSignedContent(jws), nil
}
