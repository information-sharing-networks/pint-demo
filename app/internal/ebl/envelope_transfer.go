// envelope_transfer.go provides high-level functions for creating DCSA EBL_PINT API envelope transfer requests.
//
// CreateEnvelopeTransfer is used to create a complete envelope transfer request for POST /v3/envelopes.
//
// In a production service, the sending platform would have:
// 1. The transport document JSON
// 2. The complete envelope transfer chain (array of signed entries)
// 3. Optional: eBL visualisation file
// 4. Optional: supporting documents
//
// Transfer chain entries summarize the activity that has happened to the eBL since the last time it was on this platform.
//
// In a production service, the initial receiving platform would need to:
// 2a. Create the first entry (ISSUE transaction) with the issuance manifest recieved from the carrier
// 2b. Create subsequent entries (ENDORSE , SIGN, TRANSFER, etc.) linking to the previous entry
// 2c. Include the transfer chain in the envelope transer
//
// the functions below include wrappers to help construct and sign transfer chain entries

package ebl

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
	"time"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// TODO  CreateEnvelopeTransferWithKeys etc (use in memory keys rather than files)

// EnvelopeTransferInput contains the business data needed to create a DCSA envelope transfer.
type EnvelopeTransferInput struct {

	// TransportDocument is the transport document as JSON bytes
	TransportDocument json.RawMessage

	// EnvelopeTransferChain is the complete ordered list of signed transfer chain entries
	// This must include at least one entry (the first entry with ISSUE transaction)
	EnvelopeTransferChain []crypto.EnvelopeTransferChainEntrySignedContent

	// EBLVisualizationFilePath is the optional path to the eBL visualization file (e.g., PDF)
	// If provided, the file will be read, checksummed, and metadata included in the envelope manifest
	// the binary data will be sent separately via the supporting documents API.
	// in a production system the binary data and metadata can be retrieved from the issuance request (no need to recompute from the file)
	EBLVisualizationFilePath string

	// SupportingDocumentFilePaths is an optional list of paths to supporting documents
	// If provided, each file will be read, checksummed, and metadata included in the envelope manifest
	// the binary data will be sent separately via the supporting documents API.
	SupportingDocumentFilePaths []string
}

// CreateEnvelopeTransfer creates a complete DCSA EblEnvelope ready to send to POST /v3/envelopes
//
// The signing algorithm is automatically detected from the private key type in the JWK file.
//
// Parameters:
//   - input: The data for the envelope transfer (transport document, transfer chain, optional document metadata)
//   - privateKeyJWKPath: Path to the sending platform's private key JWK file (Ed25519 or RSA)
//   - certChainFilePath: Optional path to the platform's X.509 certificate chain file (PEM format). Pass empty string if not needed.
//
// Using a cert chain file that contains an EV or OV certificate is recommended for production (used for non-repudiation)
//
// Returns the complete EblEnvelope ready to be JSON-marshaled and sent to POST /v3/envelopes
func CreateEnvelopeTransfer(
	input EnvelopeTransferInput,
	privateKeyJWKPath string,
	certChainFilePath string,
) (*crypto.EblEnvelope, error) {

	// Step 1: Validate input
	if len(input.TransportDocument) == 0 {
		return nil, fmt.Errorf("transport document is required")
	}
	if len(input.EnvelopeTransferChain) == 0 {
		return nil, fmt.Errorf("envelope transfer chain must contain at least one entry")
	}

	// Step 2: Load the private key from JWK file (auto-detects Ed25519 or RSA)
	privateKey, err := crypto.ReadPrivateKeyFromJWKFile(privateKeyJWKPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key from %s: %w", privateKeyJWKPath, err)
	}

	// Step 3: Load optional eBL visualization file and create metadata
	var eblVisualizationMetadata *crypto.DocumentMetadata
	if input.EBLVisualizationFilePath != "" {
		metadata, err := loadDocumentMetadata(input.EBLVisualizationFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load eBL visualization file: %w", err)
		}
		eblVisualizationMetadata = metadata
	}

	// Step 4: Load optional supporting documents and create metadata
	var supportingDocumentsMetadata []crypto.DocumentMetadata
	if len(input.SupportingDocumentFilePaths) > 0 {
		supportingDocumentsMetadata = make([]crypto.DocumentMetadata, 0, len(input.SupportingDocumentFilePaths))
		for i, filePath := range input.SupportingDocumentFilePaths {
			metadata, err := loadDocumentMetadata(filePath)
			if err != nil {
				return nil, fmt.Errorf("failed to load supporting document %d (%s): %w", i, filePath, err)
			}
			supportingDocumentsMetadata = append(supportingDocumentsMetadata, *metadata)
		}
	}

	// Step 5: Load the certificate chain if provided
	var certChain []*x509.Certificate
	if certChainFilePath != "" {
		chain, err := crypto.ReadCertChainFromPEMFile(certChainFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate chain: %w", err)
		}
		certChain = chain
	}

	// Step 6: Get the last entry in the transfer chain (required for envelope manifest)
	lastTransferChainEntry := input.EnvelopeTransferChain[len(input.EnvelopeTransferChain)-1]

	// Step 7: Build the envelope manifest using the builder
	manifestBuilder := crypto.NewEnvelopeManifestBuilder().
		WithTransportDocument(input.TransportDocument).
		WithLastTransferChainEntry(lastTransferChainEntry)

	if eblVisualizationMetadata != nil {
		manifestBuilder.WithEBLVisualisationByCarrier(*eblVisualizationMetadata)
	}

	if len(supportingDocumentsMetadata) > 0 {
		manifestBuilder.WithSupportingDocuments(supportingDocumentsMetadata)
	}

	envelopeManifest, err := manifestBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build envelope manifest: %w", err)
	}

	// Step 8: Sign the envelope manifest with the platform's private key
	var envelopeManifestSignedContent crypto.EnvelopeManifestSignedContent
	var keyID string

	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		publicKey := key.Public().(ed25519.PublicKey)
		keyID, err = crypto.GenerateKeyIDFromEd25519Key(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key ID: %w", err)
		}

		if len(certChain) > 0 {
			envelopeManifestSignedContent, err = envelopeManifest.SignWithEd25519AndX5C(key, keyID, certChain)
		} else {
			envelopeManifestSignedContent, err = envelopeManifest.SignWithEd25519(key, keyID)
		}

	case *rsa.PrivateKey:
		keyID, err = crypto.GenerateKeyIDFromRSAKey(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key ID: %w", err)
		}

		if len(certChain) > 0 {
			envelopeManifestSignedContent, err = envelopeManifest.SignWithRSAAndX5C(key, keyID, certChain)
		} else {
			envelopeManifestSignedContent, err = envelopeManifest.SignWithRSA(key, keyID)
		}

	default:
		return nil, fmt.Errorf("unsupported key type: %T (expected ed25519.PrivateKey or *rsa.PrivateKey)", privateKey)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign envelope manifest: %w", err)
	}

	// Step 9: Build the complete EblEnvelope using the builder
	envelope, err := crypto.NewEblEnvelopeBuilder().
		WithTransportDocument(input.TransportDocument).
		WithEnvelopeManifestSignedContent(envelopeManifestSignedContent).
		WithEnvelopeTransferChain(input.EnvelopeTransferChain).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to build EblEnvelope: %w", err)
	}

	return envelope, nil
}

// loadDocumentMetadata reads a file and creates DocumentMetadata with checksum.
// This is used for both eBL visualization and supporting documents.
func loadDocumentMetadata(filePath string) (*crypto.DocumentMetadata, error) {
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

	// Detect content type (defaults to application/octet-stream if no match)
	contentType := http.DetectContentType(content)

	// Calculate SHA-256 checksum of the binary content
	checksum, err := crypto.Hash(content)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}

	return &crypto.DocumentMetadata{
		Name:             filename,
		Size:             int64(len(content)),
		MediaType:        contentType,
		DocumentChecksum: checksum,
	}, nil
}

// GetDocumentContent reads a file and returns its base64-encoded content.
// This is used when you need to send the actual document content via the
// POST /v3/envelopes/{envelopeReference}/additional-documents/{documentChecksum} endpoint.
//
// The DCSA spec requires documents to be transferred as base64-encoded strings.
func GetDocumentContent(filePath string) (string, error) {
	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	// Read the file
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("failed to open directory %s: %w", dir, err)
	}
	defer root.Close()

	content, err := root.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Base64 encode the content
	encodedContent := base64.StdEncoding.EncodeToString(content)

	return encodedContent, nil
}

// TransferChainEntryInput contains the data needed to create an entry.
//
// Note that there are conditional fields:
//   - when isFirstEntry is true, IssuanceManifestSignedContent is required and PreviousEntryJWS should not be provided.
//   - when isFirstEntry is false, PreviousEntryJWS is required and IssuanceManifestSignedContent should not be provided.
type TransferChainEntryInput struct {

	// TransportDocumentChecksum is the SHA-256 checksum of the canonical transport document.
	// This should be the validated checksum from the carrier's IssuanceManifest.
	TransportDocumentChecksum string

	// EBLPlatform is the platform code (e.g., "WAVE", "BOLE", "CARX")
	EBLPlatform string

	// IsFirstEntry indicates if this is the first entry in the chain.
	IsFirstEntry bool

	// IssuanceManifestSignedContent is required for the first entry only
	IssuanceManifestSignedContent *crypto.IssuanceManifestSignedContent

	// ControlTrackingRegistry is optional and only for the first entry
	// Example: "https://ctr.dcsa.org/v1"
	ControlTrackingRegistry *string

	// PreviousEnvelopeTransferChainEntrySignedContent is required for subsequent entries (not first entry)
	PreviousEnvelopeTransferChainEntrySignedContent crypto.EnvelopeTransferChainEntrySignedContent

	// Transactions is the list of transactions for this entry (at least one required)
	Transactions []crypto.Transaction
}

// CreateTransferChainEntry creates and signs a transfer chain entry.
//
// Parameters:
//   - input: The data for the transfer chain entry (transport document checksum, platform, transactions, etc.)
//   - privateKeyJWKPath: Path to the platform's private key JWK file (Ed25519 or RSA)
//   - certChainFilePath: Optional path to the platform's X.509 certificate chain file (PEM format). Pass empty string to omit x5c header.
//
// Including x5c with EV/OV certificate is recommended for non-repudiation (enables offline verification)
//
// Returns the JWS signed transfer chain entry ready to include in the envelope transfer chain
func CreateTransferChainEntry(
	input TransferChainEntryInput,
	privateKeyJWKPath string,
	certChainFilePath string,
) (crypto.EnvelopeTransferChainEntrySignedContent, error) {

	// Step 1: Validate input
	if input.TransportDocumentChecksum == "" {
		return "", fmt.Errorf("transport document checksum is required")
	}
	if input.EBLPlatform == "" {
		return "", fmt.Errorf("eBL platform is required")
	}
	if len(input.Transactions) == 0 {
		return "", fmt.Errorf("at least one transaction is required")
	}

	// check first vs subsequent entry requirements
	if input.IsFirstEntry {
		if input.IssuanceManifestSignedContent == nil {
			return "", fmt.Errorf("issuance manifest is required for first entry")
		}
		if input.PreviousEnvelopeTransferChainEntrySignedContent != "" {
			return "", fmt.Errorf("previous entry JWS should not be provided for first entry")
		}
	} else {
		if input.PreviousEnvelopeTransferChainEntrySignedContent == "" {
			return "", fmt.Errorf("previous entry JWS is required for subsequent entries")
		}
		if input.IssuanceManifestSignedContent != nil {
			return "", fmt.Errorf("issuance manifest should only be provided for first entry")
		}
		if input.ControlTrackingRegistry != nil {
			return "", fmt.Errorf("control tracking registry should only be provided for first entry")
		}
	}

	// Step 2: Load the private key from JWK file
	privateKey, err := crypto.ReadPrivateKeyFromJWKFile(privateKeyJWKPath)
	if err != nil {
		return "", fmt.Errorf("failed to load private key from %s: %w", privateKeyJWKPath, err)
	}

	// Step 3: Load the certificate chain if provided
	var certChain []*x509.Certificate
	if certChainFilePath != "" {
		chain, err := crypto.ReadCertChainFromPEMFile(certChainFilePath)
		if err != nil {
			return "", fmt.Errorf("failed to load certificate chain: %w", err)
		}
		certChain = chain
	}

	// Step 4: Build the transfer chain entry using the builder
	var builder *crypto.EnvelopeTransferChainEntryBuilder

	if input.IsFirstEntry {
		builder = crypto.NewFirstEnvelopeTransferChainEntryBuilder(*input.IssuanceManifestSignedContent)
		// if provided, CTR is only included in the first entry.
		if input.ControlTrackingRegistry != nil {
			builder.WithControlTrackingRegistry(*input.ControlTrackingRegistry)
		}
	} else {
		builder = crypto.NewSubsequentEnvelopeTransferChainEntryBuilder(input.PreviousEnvelopeTransferChainEntrySignedContent)
	}

	entry, err := builder.
		WithTransportDocumentChecksum(input.TransportDocumentChecksum).
		WithEBLPlatform(input.EBLPlatform).
		WithTransactions(input.Transactions).
		Build()

	if err != nil {
		return "", fmt.Errorf("failed to build transfer chain entry: %w", err)
	}

	// Step 5: Sign the transfer chain entry with the platform's private key
	var signedContent crypto.EnvelopeTransferChainEntrySignedContent
	var keyID string

	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		publicKey := key.Public().(ed25519.PublicKey)
		keyID, err = crypto.GenerateKeyIDFromEd25519Key(publicKey)
		if err != nil {
			return "", fmt.Errorf("failed to generate key ID: %w", err)
		}

		if len(certChain) > 0 {
			signedContent, err = entry.SignWithEd25519AndX5C(key, keyID, certChain)
		} else {
			signedContent, err = entry.SignWithEd25519(key, keyID)
		}

	case *rsa.PrivateKey:
		keyID, err = crypto.GenerateKeyIDFromRSAKey(&key.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to generate key ID: %w", err)
		}

		if len(certChain) > 0 {
			signedContent, err = entry.SignWithRSAAndX5C(key, keyID, certChain)
		} else {
			signedContent, err = entry.SignWithRSA(key, keyID)
		}

	default:
		return "", fmt.Errorf("unsupported key type: %T (expected ed25519.PrivateKey or *rsa.PrivateKey)", privateKey)
	}

	if err != nil {
		return "", fmt.Errorf("failed to sign transfer chain entry: %w", err)
	}

	return signedContent, nil
}

// CreateTransferTransaction is a helper function to create a TRANSFER transaction.
//
// Parameters:
//   - actor: The party performing the transfer (must be on the sending platform)
//   - recipient: The party receiving the transfer (may be on a different platform)
func CreateTransferTransaction(actor crypto.ActorParty, recipient crypto.RecipientParty) crypto.Transaction {
	return crypto.Transaction{
		ActionCode:     "TRANSFER",
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateIssueTransaction is a helper function to create an ISSUE transaction.
//
// This is used in the first transfer chain entry when the carrier issues the eBL.
//
// Returns a Transaction ready to include in the first transfer chain entry.
func CreateIssueTransaction(actor crypto.ActorParty, recipient crypto.RecipientParty) crypto.Transaction {
	return crypto.Transaction{
		ActionCode:     "ISSUE",
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateEndorseTransaction is a helper function to create an ENDORSE transaction.
//
// This is used when a party endorses the eBL to another party.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateEndorseTransaction(actor crypto.ActorParty, recipient crypto.RecipientParty) crypto.Transaction {
	return crypto.Transaction{
		ActionCode:     "ENDORSE",
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateSignTransaction is a helper function to create a SIGN transaction.
//
// This is used when a party signs the eBL while in their possession (no recipient).
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSignTransaction(actor crypto.ActorParty) crypto.Transaction {
	return crypto.Transaction{
		ActionCode:     "SIGN",
		Actor:          actor,
		Recipient:      nil, // SIGN transactions don't have a recipient
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}
