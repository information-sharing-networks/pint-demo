package ebl

// issuance.go contains the builder for issuance manifests.
// In a production service this functionality is implemented by the carrier - a simple version is included here
// to support testing of the PINT server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

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

// WithDocument sets the transport document checksum
func (b *IssuanceManifestBuilder) WithDocumentChecksum(checksum TransportDocumentChecksum) *IssuanceManifestBuilder {
	b.documentChecksum = checksum
	return b
}

// WithIssueToChecksum sets the issueTo party (must be valid JSON)
func (b *IssuanceManifestBuilder) WithIssueToChecksum(issueToChecksum IssueToChecksum) *IssuanceManifestBuilder {
	b.issueToChecksum = issueToChecksum
	return b
}

// WithEBLVisualisation sets the eBL visualisation content checksum
func (b *IssuanceManifestBuilder) WitheBLVisualisationByCarrierChecksum(checksum EBLVisualisationByCarrierChecksum) *IssuanceManifestBuilder {
	b.eBLVisualisationByCarrierChecksum = checksum
	return b
}

// Build creates the IssuanceManifest with the supplied checksums
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
