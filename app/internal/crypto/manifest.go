// manifest.go contains functions to build DCSA IssuanceManifest and EnvelopeManifest structures
//
// These structures are used to create signed content for:
// 1. EBL Issuance (IssuanceManifest → issuanceManifestSignedContent)
// 2. PINT Transfers (EnvelopeManifest → envelopeManifestSignedContent)
//
// Issuance Flow (steps i-v):
// i)   Generate canonical JSON for document and issueTo
// ii)  Calculate SHA-256 checksums (document + issueTo)
// iii  Decode eBL visualisation from Base64 to binary (if provided) and calculate checksum
// iv)  Create IssuanceManifest with checksums (document, issueTo, eblVisualisationByCarrier)
// v)   Sign the canonical IssuanceManifest to create JWS
// vi)  Include JWS in IssuanceRequest.issuanceManifestSignedContent
//
// PINT Transfer Flow:
// i)   Generate canonical JSON for transport document
// ii)  Calculate SHA-256 checksums (document + last transfer chain entry)
// iii  Decode eBL visualisation from Base64 to binary (if provided) and calculate checksum
// iv)  Create EnvelopeManifest with checksums (transportDocument, lastTransferChainEntry, eblVisualisationByCarrier)
// v)   Sign the canonical EnvelopeManifest to create JWS
// vi)  Include JWS in EblEnvelope.envelopeManifestSignedContent

// TODO - envelopeTransferChain

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
//
// Per DCSA spec (EBL_ISS_v3.0.x):
// - documentChecksum: SHA-256 of canonicalized transport document
// - issueToChecksum: SHA-256 of canonicalized issueTo party
// - eBLVisualisationByCarrierChecksum: SHA-256 of decoded visualisation content (eblVisualisationByCarrier.content) (optional)
//
// note the eblVisualisationByCarrier.content is a Base64-encoded version of the binary content of a human redable visualisation of the ebl (typically a pdf).
type IssuanceManifest struct {
	DocumentChecksum                  string  `json:"documentChecksum"`
	IssueToChecksum                   string  `json:"issueToChecksum"`
	EBLVisualisationByCarrierChecksum *string `json:"eBLVisualisationByCarrierChecksum,omitempty"`
}

// IssuanceManifestBuilder is used to build IssuanceManifest with DCSA-compliant checksums
type IssuanceManifestBuilder struct {
	documentJSON                     []byte
	issueToJSON                      []byte
	eblVisualisationByCarrierContent string // Base64-encoded string from JSON
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
func (b *IssuanceManifestBuilder) WithEBLVisualisation(base64Content string) *IssuanceManifestBuilder {
	b.eblVisualisationByCarrierContent = base64Content
	return b
}

// Build creates the IssuanceManifest with calculated checksums
//
// Performs DCSA steps i-iii:
// i)   Canonicalize JSON documents per RFC 8785
// ii)  Calculate SHA-256 checksums
// iii) Create IssuanceManifest object
func (b *IssuanceManifestBuilder) Build() (*IssuanceManifest, error) {
	// Validate required fields
	if len(b.documentJSON) == 0 {
		return nil, fmt.Errorf("document is required")
	}
	if len(b.issueToJSON) == 0 {
		return nil, fmt.Errorf("issueTo is required")
	}

	// Step i: Canonicalize JSON documents
	canonicalDocument, err := CanonicalizeJSON(b.documentJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize document: %w", err)
	}

	canonicalIssueTo, err := CanonicalizeJSON(b.issueToJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize issueTo: %w", err)
	}

	// Step ii: Calculate SHA-256 checksums
	documentChecksum, err := Hash(canonicalDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to hash document: %w", err)
	}
	issueToChecksum, err := Hash(canonicalIssueTo)
	if err != nil {
		return nil, fmt.Errorf("failed to hash issueTo: %w", err)
	}

	// Step iii: Create IssuanceManifest
	manifest := &IssuanceManifest{
		DocumentChecksum: documentChecksum,
		IssueToChecksum:  issueToChecksum,
	}

	// BL visualisation checksum (if provided) - content is base64 encoded
	if len(b.eblVisualisationByCarrierContent) > 0 {

		visualisationChecksum, err := HashFromBase64(
			b.eblVisualisationByCarrierContent,
			MaxDocumentSize,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to hash eBL visualisation: %w", err)
		}
		manifest.EBLVisualisationByCarrierChecksum = &visualisationChecksum
	}

	return manifest, nil
}

// SignWithEd25519AndX5C creates the issuanceManifestSignedContent JWS string using Ed25519
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithEd25519AndX5C(privateKey ed25519.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}
	jws, err := SignJSONWithEd25519AndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}

// SignWithEd25519 creates the issuanceManifestSignedContent JWS string using Ed25519 (no x5c header)
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithEd25519(privateKey ed25519.PrivateKey, keyID string) (string, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}

	jws, err := SignJSONWithEd25519(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}

// SignWithRSAAndX5C creates the issuanceManifestSignedContent JWS string using RSA
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithRSAAndX5C(privateKey *rsa.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}
	jws, err := SignJSONWithRSAAndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}

// SignWithRSA creates the issuanceManifestSignedContent JWS string using RSA (no x5c header)
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) SignWithRSA(privateKey *rsa.PrivateKey, keyID string) (string, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}

	jws, err := SignJSONWithRSA(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}

// EnvelopeManifest represents the DCSA EnvelopeManifest structure
// This is used for PINT envelope transfers
//
// Per DCSA spec (EBL_PINT_v3.0.x):
// - transportDocumentChecksum: SHA-256 of canonicalized transport document
// - lastEnvelopeTransferChainEntrySignedContentChecksum: SHA-256 of last transfer chain entry JWS
type EnvelopeManifest struct {
	TransportDocumentChecksum                           string  `json:"transportDocumentChecksum"`
	LastEnvelopeTransferChainEntrySignedContentChecksum string  `json:"lastEnvelopeTransferChainEntrySignedContentChecksum"`
	EBLVisualisationByCarrierChecksum                   *string `json:"eBLVisualisationByCarrierChecksum,omitempty"`
}

// EnvelopeManifestBuilder helps build EnvelopeManifest for PINT transfers
type EnvelopeManifestBuilder struct {
	transportDocumentJSON            []byte
	lastTransferChainJWS             string // JWS compact serialization
	eblVisualisationByCarrierContent string // Base64-encoded string from JSON
}

// NewEnvelopeManifestBuilder creates a new builder for EnvelopeManifest
func NewEnvelopeManifestBuilder() *EnvelopeManifestBuilder {
	return &EnvelopeManifestBuilder{}
}

// WithTransportDocument sets the transport document (must be valid JSON)
func (b *EnvelopeManifestBuilder) WithTransportDocument(documentJSON []byte) *EnvelopeManifestBuilder {
	b.transportDocumentJSON = documentJSON
	return b
}

// WithLastTransferChainEntry sets the last transfer chain entry JWS
// This is the JWS compact serialization of the last EnvelopeTransferChainEntry
func (b *EnvelopeManifestBuilder) WithLastTransferChainEntry(jwsString string) *EnvelopeManifestBuilder {
	b.lastTransferChainJWS = jwsString
	return b
}

// WithEBLVisualisation sets the eBL visualisation content.
//
// Expects the base64-encoded string from eblVisualisationByCarrier.content field in the JSON.
// The content will be decoded before calculating the checksum - Build() will return an error if the content is not valid base64.
func (b *EnvelopeManifestBuilder) WithEBLVisualisation(base64Content string) *EnvelopeManifestBuilder {
	b.eblVisualisationByCarrierContent = base64Content
	return b
}

// Build creates the EnvelopeManifest with calculated checksums
//
// Performs DCSA checksum calculations:
// - Canonicalize transport document and calculate SHA-256
// - Calculate SHA-256 of last transfer chain entry JWS
// - Optionally calculate SHA-256 of eBL visualisation
//
// Returns error if:
// - transport document or last transfer chain entry is missing
// - JSON canonicalization fails
func (b *EnvelopeManifestBuilder) Build() (*EnvelopeManifest, error) {
	// Validate required fields
	if len(b.transportDocumentJSON) == 0 {
		return nil, fmt.Errorf("transport document is required")
	}
	if b.lastTransferChainJWS == "" {
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

	// Per DCSA: "The checksum is computed over the entire EnvelopeTransferChainEntrySignedContent entry"
	// The JWS string itself is the signed content, so we hash the entire JWS string
	lastTransferChainChecksum, err := Hash([]byte(b.lastTransferChainJWS))
	if err != nil {
		return nil, fmt.Errorf("failed to hash last transfer chain entry: %w", err)
	}

	// Create EnvelopeManifest
	manifest := &EnvelopeManifest{
		TransportDocumentChecksum:                           transportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: lastTransferChainChecksum,
	}

	// Optional: eBL visualisation checksum
	if len(b.eblVisualisationByCarrierContent) > 0 {
		// Per DCSA: Decode from BASE64 to binary before calculating checksum
		// Use streaming decode to avoid loading large PDFs into memory
		// MaxDocumentSize limit is enforced on the base64 string length
		visualisationChecksum, err := HashFromBase64(
			b.eblVisualisationByCarrierContent,
			MaxDocumentSize,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to hash eBL visualisation: %w", err)
		}
		manifest.EBLVisualisationByCarrierChecksum = &visualisationChecksum
	}

	return manifest, nil
}

// SignWithEd25519AndX5C creates the envelopeManifestSignedContent JWS string using Ed25519
// This performs DCSA step iv: sign the canonical EnvelopeManifest
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithEd25519AndX5C(privateKey ed25519.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize manifest: %w", err)
	}

	jws, err := SignJSONWithEd25519AndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}

// SignWithEd25519 creates the envelopeManifestSignedContent JWS string using Ed25519 (no x5c header
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithEd25519(privateKey ed25519.PrivateKey, keyID string) (string, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize manifest: %w", err)
	}

	jws, err := SignJSONWithEd25519(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}

// SignWithRSAAndX5C creates the envelopeManifestSignedContent JWS string using RSA
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithRSAAndX5C(privateKey *rsa.PrivateKey, keyID string, certChain []*x509.Certificate) (string, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize manifest: %w", err)
	}

	jws, err := SignJSONWithRSAAndX5C(jsonBytes, privateKey, keyID, certChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}

// SignWithRSA creates the envelopeManifestSignedContent JWS string using RSA (no x5c header)
//
// Returns a JWS compact serialization string ready to include in EblEnvelope.envelopeManifestSignedContent
func (m *EnvelopeManifest) SignWithRSA(privateKey *rsa.PrivateKey, keyID string) (string, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize manifest: %w", err)
	}

	jws, err := SignJSONWithRSA(jsonBytes, privateKey, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign manifest: %w", err)
	}

	return jws, nil
}
