package ebl

// issuance.go contains the builders for issuance manifests.

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// IssuanceManifest is signed by the carrier and included with the initial issuance.
// This is the payload that gets signed in issuanceManifestSignedContent
type IssuanceManifest struct {

	// DocumentChecksum: SHA-256 of canonicalized transport document JSON
	DocumentChecksum TransportDocumentChecksum `json:"documentChecksum"`

	// IssueToChecksum: SHA-256 of canonicalized issueTo party JSON
	IssueToChecksum IssueToChecksum `json:"issueToChecksum"`

	// EBLVisualisationByCarrierChecksum: SHA-256 of decoded visualisation content (optional)
	EBLVisualisationByCarrierChecksum *EBLVisualisationByCarrierChecksum `json:"eBLVisualisationByCarrierChecksum,omitempty"`
}

// ValidateStructure checks that all required fields are present per DCSA EBL_ISS specification
func (i *IssuanceManifest) ValidateStructure() error {
	if i.DocumentChecksum == "" {
		return NewIssuanceBadRequestError("documentChecksum is required")
	}
	if i.IssueToChecksum == "" {
		return NewIssuanceBadRequestError("issueToChecksum is required")
	}
	return nil
}

// IssuanceManifestSignedContent a compact JWS serialization of an IssuanceManifest.
type IssuanceManifestSignedContent string

// IssueToChecksum is the SHA-256 checksum of the canonicalized issueTo party JSON.
type IssueToChecksum string

// Payload extract the eBL visualization from the manifest
// Note this function does not verify the JWS signature.
func (i IssuanceManifestSignedContent) Payload() (*IssuanceManifest, error) {
	parts := strings.Split(string(i), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	manifestPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode manifest JWS payload %v", err)
	}

	var issuanceManifest IssuanceManifest
	if err := json.Unmarshal(manifestPayload, &issuanceManifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal issuance manifest: %v", err)
	}
	return &issuanceManifest, nil
}

// Checksum returns the SHA-256 checksum of the issuance manifest JWS token.
func (i IssuanceManifestSignedContent) Checksum() (string, error) {
	c, err := crypto.Hash([]byte(i))
	if err != nil {
		return "", fmt.Errorf("failed to crypto.Hash issuance manifest: %w", err)
	}
	return c, nil
}

// Header extracts the JWS header from the issuance manifest.
func (i IssuanceManifestSignedContent) Header() (crypto.JWSHeader, error) {
	return crypto.ParseJWSHeader(string(i))
}

// IssuanceManifestBuilder is used to build IssuanceManifest with DCSA-compliant checksums
type IssuanceManifestBuilder struct {
	documentChecksum                  TransportDocumentChecksum
	issueToChecksum                   IssueToChecksum
	eBLVisualisationByCarrierChecksum EBLVisualisationByCarrierChecksum
}

// EBLVisualisationByCarrierChecksum is the SHA-256 checksum of the decoded eBL visualisation content.
type EBLVisualisationByCarrierChecksum string

// NewIssuanceManifestBuilder creates a new builder for IssuanceManifest.
func NewIssuanceManifestBuilder() *IssuanceManifestBuilder {
	return &IssuanceManifestBuilder{}
}

// WithDocument sets the transport document (must be valid JSON)
// The document will be canonicalized by the Build() method before checksum calculation
func (b *IssuanceManifestBuilder) WithDocumentChecksum(checksum TransportDocumentChecksum) *IssuanceManifestBuilder {
	b.documentChecksum = checksum
	return b
}

// WithIssueTo sets the issueTo party (must be valid JSON)
// The issueTo will be canonicalized by the Build() method before checksum calculation
func (b *IssuanceManifestBuilder) WithIssueTo(issueToChecksum IssueToChecksum) *IssuanceManifestBuilder {
	b.issueToChecksum = issueToChecksum
	return b
}

// WithEBLVisualisation sets the eBL visualisation content.
//
// Expects the base64-encoded string from eblVisualisationByCarrier.content field in the JSON.
// The content will be decoded before calculating the checksum - Build() will return an error if the content is not valid base64.
func (b *IssuanceManifestBuilder) WitheBLVisualisationByCarrierChecksum(checksum EBLVisualisationByCarrierChecksum) *IssuanceManifestBuilder {
	b.eBLVisualisationByCarrierChecksum = checksum
	return b
}

// Build creates the IssuanceManifest with calculated checksums
// for the document JSON, issueTo JSON and (optionally) eblVisualisationByCarrier content
// the function will
//
//   - canonicalize the JSON documents
//   - calculate the SHA-256 checksums for the canonical JSON documents
//   - calculate the SHA-256 checksum of the decoded eblVisualisationByCarrier content (if provided)
func (b *IssuanceManifestBuilder) Build() (*IssuanceManifest, error) {

	issuanceManifest := &IssuanceManifest{
		DocumentChecksum: b.documentChecksum,
		IssueToChecksum:  IssueToChecksum(b.issueToChecksum),
	}
	if b.eBLVisualisationByCarrierChecksum != "" {
		issuanceManifest.EBLVisualisationByCarrierChecksum = &b.eBLVisualisationByCarrierChecksum
	}
	if err := issuanceManifest.ValidateStructure(); err != nil {
		return nil, err
	}

	return issuanceManifest, nil
}

// Sign creates the issuanceManifestSignedContent JWS string.
//
// The privateKey can be either ed25519.PrivateKey or *rsa.PrivateKey.
// If certChain is provided, the x5c header will be included in the JWS for non-repudiation.
//
// Returns a JWS compact serialization string ready to include in IssuanceRequest.issuanceManifestSignedContent
func (m *IssuanceManifest) Sign(privateKey any, certChain []*x509.Certificate) (IssuanceManifestSignedContent, error) {
	// Marshal to JSON
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", WrapInternalError(err, "failed to marshal issuance manifest")
	}

	// Sign
	jws, err := crypto.SignJSON(jsonBytes, privateKey, certChain)
	if err != nil {
		return "", WrapSignatureError(err, "failed to sign manifest")
	}

	return IssuanceManifestSignedContent(jws), nil
}
