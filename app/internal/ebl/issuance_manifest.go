package ebl

// issuance.go implements DCSA EBL_ISS specification for issuance manifests.
//
// these functions are included to allow the pint-demo app to do a full end to end flow of the DCSA APIs from issuance to surrender
//
// If you're creating an IssuanceRequest for the DCSA API, you probably want
// the wrapper functions in issuance_request.go, but if you need fine grained control, you can use the functions in this file.
//
// This file contains:
//  - IssuanceManifest type and methods
//  - IssuanceManifestBuilder for custom workflows
//  - calls out to Low-level signing methods
//
// # DCSA Issuance Flow (performed by the carrier)
//
//  i)   Generate canonical JSON for document and issueTo
//  ii)  Calculate SHA-256 checksums (document + issueTo)
//  iii) Decode eBL visualisation (if provided) from Base64 to binary and calculate checksum
//  iv)  Create IssuanceManifest with checksums (document, issueTo, eblVisualisationByCarrier)
//  v)   Sign the canonical IssuanceManifest to create JWS
//  vi)  Include JWS in IssuanceRequest.issuanceManifestSignedContent

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// IssuanceManifest represents the DCSA IssuanceManifest structure
// the issuance manifest is used to verify the transport document and the issueTo party have not been tampered with.
// This is the payload that gets signed in issuanceManifestSignedContent
type IssuanceManifest struct {

	// DocumentChecksum: SHA-256 of canonicalized transport document JSON
	DocumentChecksum string `json:"documentChecksum"`

	// IssueToChecksum: SHA-256 of canonicalized issueTo party JSON
	IssueToChecksum string `json:"issueToChecksum"`

	// EBLVisualisationByCarrierChecksum: SHA-256 of decoded visualisation content (optional)
	EBLVisualisationByCarrierChecksum *string `json:"eBLVisualisationByCarrierChecksum,omitempty"`
}

// IssuanceManifestSignedContent represents a JWS compact serialization of an IssuanceManifest.
type IssuanceManifestSignedContent string

// Validate checks that all required fields are present per DCSA EBL_ISS specification
func (i *IssuanceManifest) Validate() error {
	if i.DocumentChecksum == "" {
		return NewIssuanceBadRequestError("documentChecksum is required")
	}
	if i.IssueToChecksum == "" {
		return NewIssuanceBadRequestError("issueToChecksum is required")
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
		return NewIssuanceBadRequestError("name is required")
	}
	if e.Content == "" {
		return NewIssuanceBadRequestError("content is required")
	}
	if e.ContentType == "" {
		return NewIssuanceBadRequestError("contentType is required")
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

// Build creates the IssuanceManifest with calculated checksums
// for the document JSON, issueTo JSON and (optionally) eblVisualisationByCarrier content
// the function will
//
//   - canonicalize the JSON documents
//   - calculate the SHA-256 checksums for the canonical JSON documents
//   - calculate the SHA-256 checksum of the decoded eblVisualisationByCarrier content (if provided)
func (b *IssuanceManifestBuilder) Build() (*IssuanceManifest, error) {

	// Validate required fields
	if len(b.documentJSON) == 0 {
		return nil, NewIssuanceBadRequestError("document is required")
	}
	if len(b.issueToJSON) == 0 {
		return nil, NewIssuanceBadRequestError("issueTo is required")
	}

	// Canonicalize JSON documents
	canonicalDocument, err := crypto.CanonicalizeJSON(b.documentJSON)
	if err != nil {
		return nil, WrapIssuanceBadRequestError(err, "failed to canonicalize document")
	}

	canonicalIssueTo, err := crypto.CanonicalizeJSON(b.issueToJSON)
	if err != nil {
		return nil, WrapIssuanceBadRequestError(err, "failed to canonicalize issueTo")
	}

	// Calculate SHA-256 checksums
	documentChecksum, err := crypto.Hash(canonicalDocument)
	if err != nil {
		return nil, WrapInternalError(err, "failed to crypto.Hash document")
	}
	issueToChecksum, err := crypto.Hash(canonicalIssueTo)
	if err != nil {
		return nil, WrapInternalError(err, "failed to crypto.Hash issueTo")
	}

	// Create IssuanceManifest
	issuanceManifest := &IssuanceManifest{
		DocumentChecksum: documentChecksum,
		IssueToChecksum:  issueToChecksum,
	}

	// add eBL visualisation checksum
	if b.eBLVisualisationByCarrier != nil {
		if err := b.eBLVisualisationByCarrier.Validate(); err != nil {
			return nil, crypto.WrapValidationError(err, "eBLVisualisationByCarrier")
		}

		// TODO check mime type is consistent with binary content?

		// the checksum is calculated from the decoded binary content
		visualisationChecksum, err := crypto.HashFromBase64(
			b.eBLVisualisationByCarrier.Content,
		)
		if err != nil {
			return nil, crypto.WrapValidationError(err, "failed to crypto.Hash eBL visualisation")
		}
		issuanceManifest.EBLVisualisationByCarrierChecksum = &visualisationChecksum
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

	// Generate keyID from public key (thumbprint) and sign
	var jws string
	var keyID string

	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		publicKey := key.Public().(ed25519.PublicKey)
		keyID, err = crypto.GenerateKeyIDFromEd25519Key(publicKey)
		if err != nil {
			return "", WrapInternalError(err, "failed to generate keyID from public key")
		}

		if len(certChain) > 0 {
			jws, err = crypto.SignJSONWithEd25519AndX5C(jsonBytes, key, keyID, certChain)
		} else {
			jws, err = crypto.SignJSONWithEd25519(jsonBytes, key, keyID)
		}

	case *rsa.PrivateKey:
		keyID, err = crypto.GenerateKeyIDFromRSAKey(&key.PublicKey)
		if err != nil {
			return "", WrapInternalError(err, "failed to generate keyID from public key")
		}

		if len(certChain) > 0 {
			jws, err = crypto.SignJSONWithRSAAndX5C(jsonBytes, key, keyID, certChain)
		} else {
			jws, err = crypto.SignJSONWithRSA(jsonBytes, key, keyID)
		}

	default:
		return "", NewIssuanceBadRequestError(fmt.Sprintf("unsupported key type: %T (expected ed25519.PrivateKey or *rsa.PrivateKey)", privateKey))
	}

	if err != nil {
		return "", WrapSignatureError(err, "failed to sign manifest")
	}

	return IssuanceManifestSignedContent(jws), nil
}
