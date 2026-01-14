// issuanceRequest.go provides high-level functions for creating DCSA EBL_ISS API issuace requests.
//
// CreateIssuanceRequest is used in the demo app to simulate the initial issuance request from the carrier to the ebl platform (PUT /v3/ebl-issuance-requests)
//
// In a production service the carrier would have already created the Visualisation
// file and documentJSON, issueTo JSON and would need to:
// 1. create the issuance manifest and sign it
// 2. create the eblVisualisationByCarrier struct with the base64 encoded content
// 3. construct the issuance request json combining the document JSON, issueTo JSON, eblVisualisationByCarrier and issuanceManifestSignedContent
//
// the CreateIssuanceRequest function shows how to use the low level functions to perform these steps.
package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// IssuanceRequestInput contains the business data needed to create a DCSA IssuanceRequest.
//
// This struct contains only the payload data that will be included in the request,
// not the signing credentials (private key, certificate chain).
type IssuanceRequestInput struct {

	// Document is the transport document as JSON bytes
	Document json.RawMessage

	// IssueTo is the party receiving the eBL as JSON bytes
	IssueTo json.RawMessage

	// EBLVisualisationFilePath is the optional path to the eBL Visualisation file (e.g., PDF).
	EBLVisualisationFilePath string
}

// IssuanceRequest is the complete DCSA API request structure for PUT /v3/ebl-issuance-requests.
//
// This is the final structure that is sent to the DCSA issuance request endpoint (PUT /v3/ebl-issuance-requests)
type IssuanceRequest struct {

	// Document is the transport document
	Document json.RawMessage `json:"document"`

	// IssueTo is the party receiving the eBL
	IssueTo json.RawMessage `json:"issueTo"`

	// EBLVisualisationByCarrier is the optional Visualisation (e.g., PDF)
	EBLVisualisationByCarrier *EBLVisualisationByCarrier `json:"eBLVisualisationByCarrier,omitempty"`

	// IssuanceManifestSignedContent is the JWS signature proving integrity
	IssuanceManifestSignedContent IssuanceManifestSignedContent `json:"issuanceManifestSignedContent"`
}

// Algorithm specifies which signing algorithm to use
type Algorithm string

const (
	AlgorithmEd25519 Algorithm = "EdDSA"
	AlgorithmRSA     Algorithm = "RS256"
)

// CreateIssuanceRequest creates a complete DCSA IssuanceRequest ready to send to the API (PUT /v3/ebl-issuance-requests)
//
// Parameters
//   - input: The data for the issuance request (document, issueTo, [optional] path to Visualisation)
//   - signingAlgorithm: The signing algorithm to use (EdDSA or RS256)
//   - privateKeyJWKPath: Path to the carriers' private key JWK file (must match the signing algorithm)
//   - certChainFilePath: Optional path to the carrier's X.509 certificate chain file (PEM format). Pass empty string if not needed.
//
// using a cert chain file that contains an EV or OV certificate is recommended for production (used for non-repudiation)
func CreateIssuanceRequest(
	issuanceRequestInput IssuanceRequestInput,
	signingAlgorithm Algorithm,
	privateKeyJWKPath string,
	certChainFilePath string,
) (*IssuanceRequest, error) {

	// Step 1: Load the private key from JWK file
	var privateKey any
	var err error

	switch signingAlgorithm {
	case AlgorithmEd25519:
		ed25519Key, err := ReadEd25519PrivateKeyFromJWKFile(privateKeyJWKPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load Ed25519 private key from %s: %w", privateKeyJWKPath, err)
		}
		privateKey = ed25519Key

	case AlgorithmRSA:
		rsaKey, err := ReadRSAPrivateKeyFromJWKFile(privateKeyJWKPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load RSA private key from %s: %w", privateKeyJWKPath, err)
		}
		privateKey = rsaKey

	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s (expected %s or %s)", signingAlgorithm, AlgorithmEd25519, AlgorithmRSA)
	}

	// Step 2: create metadata for the eBL Visualisation file if provided
	var eBLVisualisationByCarrier *EBLVisualisationByCarrier
	if issuanceRequestInput.EBLVisualisationFilePath != "" {
		v, err := loadEblVisualisationFile(issuanceRequestInput.EBLVisualisationFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load Visualisation file: %w", err)
		}
		eBLVisualisationByCarrier = v
	}

	// Step 3: Load the certificate chain if provided
	var certChain []*x509.Certificate
	if certChainFilePath != "" {
		chain, err := ReadCertChainFromPEMFile(certChainFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate chain: %w", err)
		}
		certChain = chain
	}

	// Step 4: Build the issuanceManifest using the builder
	builder := NewIssuanceManifestBuilder().
		WithDocument(issuanceRequestInput.Document).
		WithIssueTo(issuanceRequestInput.IssueTo)

	if eBLVisualisationByCarrier != nil {
		builder.WithEBLVisualisation(eBLVisualisationByCarrier)
	}

	issuanceManifest, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build issuance manifest: %w", err)
	}

	// Step 5: Generate key ID (thumbprint of public key) and sign the issuance manifest
	var issuanceManifestSignedContent IssuanceManifestSignedContent
	var keyID string

	switch key := privateKey.(type) {
	case ed25519.PrivateKey:

		publicKey := key.Public().(ed25519.PublicKey)
		keyID, err = GenerateKeyIDFromEd25519Key(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key ID: %w", err)
		}

		if len(certChain) > 0 {
			issuanceManifestSignedContent, err = issuanceManifest.SignWithEd25519AndX5C(key, keyID, certChain)
		} else {
			issuanceManifestSignedContent, err = issuanceManifest.SignWithEd25519(key, keyID)
		}
	case *rsa.PrivateKey:

		keyID, err = GenerateKeyIDFromRSAKey(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key ID: %w", err)
		}

		if len(certChain) > 0 {
			issuanceManifestSignedContent, err = issuanceManifest.SignWithRSAAndX5C(key, keyID, certChain)
		} else {
			issuanceManifestSignedContent, err = issuanceManifest.SignWithRSA(key, keyID)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %T (expected ed25519.PrivateKey or *rsa.PrivateKey)", privateKey)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to sign issuance manifest: %w", err)
	}

	// Step 6: Assemble the complete IssuanceRequest
	return &IssuanceRequest{
		Document:                      issuanceRequestInput.Document,
		IssueTo:                       issuanceRequestInput.IssueTo,
		EBLVisualisationByCarrier:     eBLVisualisationByCarrier,
		IssuanceManifestSignedContent: issuanceManifestSignedContent,
	}, nil
}

// loadEblVisualisationFile reads a file and creates an EBLVisualisationByCarrier.
// TODO - move to a separate document.go file?
func loadEblVisualisationFile(filePath string) (*EBLVisualisationByCarrier, error) {
	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	// Read the file
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory %s: %w", dir, err)
	}
	defer root.Close()

	content, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Detect content type (note defaults to application/octet-stream if no match)
	contentType := http.DetectContentType(content)

	// Base64 encode the content
	encodedContent := base64.StdEncoding.EncodeToString(content)

	return &EBLVisualisationByCarrier{
		Name:        filename,
		ContentType: contentType,
		Content:     encodedContent,
	}, nil
}
