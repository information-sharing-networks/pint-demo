package ebl

// envelope_transfer.go provides high-level functions for creating DCSA EBL_PINT API envelope transfer requests.
//
// CreateEnvelopeTransfer is used to create a complete envelope transfer request for POST /v3/envelopes.
//
// In a production service, the sending platform would have:
// a. The transport document JSON
// b. The complete envelope transfer chain (array of signed entries)
// c. Optional: eBL visualisation file
// d. Optional: supporting documents
//
// Transfer chain entries summarize the activity that has happened to the eBL since the last time it was on this platform.
//
// In a production service, the initial receiving platform would need to:
// 1. Create the first entry (ISSUE transaction) with the issuance manifest received from the carrier
// 2. Create subsequent entries (ENDORSE, SIGN, TRANSFER, etc.) linking to the previous entry
// 3. Include the transfer chain in the envelope transfer
//
// The functions below include wrappers to help construct and sign transfer chain entries.

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// EnvelopeTransferInput contains the business data needed to create a DCSA envelope transfer.
type EnvelopeTransferInput struct {

	// TransportDocument is the transport document as JSON bytes
	TransportDocument json.RawMessage

	// EnvelopeTransferChain is the complete ordered list of signed transfer chain entries
	// This must include at least one entry (the first entry with ISSUE transaction)
	EnvelopeTransferChain []EnvelopeTransferChainEntrySignedContent

	// EBLVisualizationFilePath is the optional path to the eBL visualization file (e.g., PDF)
	// If provided, the file will be read, checksummed, and metadata included in the envelope manifest.
	// The binary data will be sent separately via the supporting documents API.
	// In a production system the binary data and metadata can be retrieved from the issuance request (no need to recompute from the file).
	EBLVisualizationFilePath string

	// SupportingDocumentFilePaths is an optional list of paths to supporting documents.
	// If provided, each file will be read, checksummed, and metadata included in the envelope manifest.
	// The binary data will be sent separately via the supporting documents API.
	SupportingDocumentFilePaths []string
}

// CreateEnvelopeTransfer creates a complete DCSA EblEnvelope ready to send to POST /v3/envelopes.
//
// The signing algorithm is automatically detected from the private key type (ed25519.PrivateKey or *rsa.PrivateKey).
//
// Parameters:
//   - input: The data for the envelope transfer (transport document, transfer chain, optional document metadata)
//   - privateKey: The sending platform's private key (ed25519.PrivateKey or *rsa.PrivateKey)
//   - certChain: Optional X.509 certificate chain. Pass nil if not needed.
//
// Using a cert chain with an EV or OV certificate is recommended for production (used for non-repudiation).
//
// Returns the complete EblEnvelope ready to be JSON-marshaled and sent to POST /v3/envelopes.
func CreateEnvelopeTransfer(
	input EnvelopeTransferInput,
	privateKey any,
	certChain []*x509.Certificate,
) (*EblEnvelope, error) {

	// Step 1: Validate input
	if len(input.TransportDocument) == 0 {
		return nil, NewEnvelopeError("transport document is required")
	}
	if len(input.EnvelopeTransferChain) == 0 {
		return nil, NewEnvelopeError("envelope transfer chain must contain at least one entry")
	}

	// Step 2: Load optional eBL visualization file and create metadata
	var eblVisualizationMetadata *DocumentMetadata
	if input.EBLVisualizationFilePath != "" {
		metadata, err := loadDocumentMetadata(input.EBLVisualizationFilePath)
		if err != nil {
			return nil, WrapEnvelopeError(err, "failed to load eBL visualization file")
		}
		eblVisualizationMetadata = metadata
	}

	// Step 3: Load optional supporting documents and create metadata
	var supportingDocumentsMetadata []DocumentMetadata
	if len(input.SupportingDocumentFilePaths) > 0 {
		supportingDocumentsMetadata = make([]DocumentMetadata, 0, len(input.SupportingDocumentFilePaths))
		for i, filePath := range input.SupportingDocumentFilePaths {
			metadata, err := loadDocumentMetadata(filePath)
			if err != nil {
				return nil, WrapEnvelopeError(err, fmt.Sprintf("failed to load supporting document %d (%s)", i, filePath))
			}
			supportingDocumentsMetadata = append(supportingDocumentsMetadata, *metadata)
		}
	}

	// Step 4: Get the last entry in the transfer chain (required for envelope manifest)
	lastTransferChainEntry := input.EnvelopeTransferChain[len(input.EnvelopeTransferChain)-1]

	// Step 5: Build the envelope manifest using the builder
	manifestBuilder := NewEnvelopeManifestBuilder().
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
		return nil, WrapEnvelopeError(err, "failed to build envelope manifest")
	}

	// Step 6: Sign the envelope manifest with the platform's private key
	envelopeManifestSignedContent, err := envelopeManifest.Sign(privateKey, certChain)
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to sign envelope manifest")
	}

	// Step 7: Build the complete EblEnvelope using the builder
	envelope, err := NewEblEnvelopeBuilder().
		WithTransportDocument(input.TransportDocument).
		WithEnvelopeManifestSignedContent(envelopeManifestSignedContent).
		WithEnvelopeTransferChain(input.EnvelopeTransferChain).
		Build()

	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to build EblEnvelope")
	}

	return envelope, nil
}

// loadDocumentMetadata reads a file and creates DocumentMetadata with checksum.
// This is used for both eBL visualization and supporting documents.
func loadDocumentMetadata(filePath string) (*DocumentMetadata, error) {
	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	// Read the file
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, WrapEnvelopeError(err, fmt.Sprintf("failed to open directory %s", dir))
	}
	defer root.Close()

	content, err := root.ReadFile(filename)
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to read file")
	}

	// Detect content type (defaults to application/octet-stream if no match)
	contentType := http.DetectContentType(content)

	// Calculate SHA-256 checksum of the binary content
	checksum, err := crypto.Hash(content)
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to calculate checksum")
	}

	return &DocumentMetadata{
		Name:             filename,
		Size:             int64(len(content)),
		MediaType:        contentType,
		DocumentChecksum: checksum,
	}, nil
}

// TransferChainEntryInput contains the data needed to create a transfer chain entry.
//
// Note that there are conditional fields:
//   - When IsFirstEntry is true, IssuanceManifestSignedContent is required and PreviousEnvelopeTransferChainEntrySignedContent should not be provided.
//   - When IsFirstEntry is false, PreviousEnvelopeTransferChainEntrySignedContent is required and IssuanceManifestSignedContent should not be provided.
type TransferChainEntryInput struct {

	// TransportDocumentChecksum is the SHA-256 checksum of the canonical transport document.
	// This should be the validated checksum from the carrier's IssuanceManifest.
	TransportDocumentChecksum string

	// EBLPlatform is the platform code (e.g., "WAVE", "BOLE", "CARX")
	EBLPlatform string

	// IsFirstEntry indicates if this is the first entry in the chain.
	IsFirstEntry bool

	// IssuanceManifestSignedContent is required for the first entry only.
	IssuanceManifestSignedContent *IssuanceManifestSignedContent

	// ControlTrackingRegistry is optional and only for the first entry.
	// Example: "https://ctr.dcsa.org/v1"
	ControlTrackingRegistry *string

	// PreviousEnvelopeTransferChainEntrySignedContent is required for subsequent entries (not first entry).
	PreviousEnvelopeTransferChainEntrySignedContent EnvelopeTransferChainEntrySignedContent

	// Transactions is the list of transactions for this entry (at least one required).
	Transactions []Transaction
}

// CreateTransferChainEntrySignedContent creates and signs a transfer chain entry.
//
// Parameters:
//   - input: The data for the transfer chain entry (transport document checksum, platform, transactions, etc.)
//   - privateKey: The platform's private key (ed25519.PrivateKey or *rsa.PrivateKey)
//   - certChain: Optional X.509 certificate chain. Pass nil to omit x5c header.
//
// Including x5c with EV/OV certificate is recommended for non-repudiation (enables offline verification).
//
// Returns the JWS signed transfer chain entry ready to include in the envelope transfer chain.
func CreateTransferChainEntrySignedContent(
	input TransferChainEntryInput,
	privateKey any,
	certChain []*x509.Certificate,
) (EnvelopeTransferChainEntrySignedContent, error) {

	// Step 1: Validate input
	if input.TransportDocumentChecksum == "" {
		return "", NewEnvelopeError("transport document checksum is required")
	}
	if input.EBLPlatform == "" {
		return "", NewEnvelopeError("eBL platform is required")
	}
	if len(input.Transactions) == 0 {
		return "", NewEnvelopeError("at least one transaction is required")
	}

	// check first vs subsequent entry requirements
	if input.IsFirstEntry {
		if input.IssuanceManifestSignedContent == nil {
			return "", NewEnvelopeError("issuance manifest is required for first entry")
		}
		if input.PreviousEnvelopeTransferChainEntrySignedContent != "" {
			return "", NewEnvelopeError("previous entry JWS should not be provided for first entry")
		}
	} else {
		if input.PreviousEnvelopeTransferChainEntrySignedContent == "" {
			return "", NewEnvelopeError("previous entry JWS is required for subsequent entries")
		}
		if input.IssuanceManifestSignedContent != nil {
			return "", NewEnvelopeError("issuance manifest should only be provided for first entry")
		}
		if input.ControlTrackingRegistry != nil {
			return "", NewEnvelopeError("control tracking registry should only be provided for first entry")
		}
	}

	// Step 2: Build the transfer chain entry using the builder
	var builder *EnvelopeTransferChainEntryBuilder

	if input.IsFirstEntry {
		builder = NewFirstEnvelopeTransferChainEntryBuilder(*input.IssuanceManifestSignedContent)
		// If provided, CTR is only included in the first entry.
		if input.ControlTrackingRegistry != nil {
			builder.WithControlTrackingRegistry(*input.ControlTrackingRegistry)
		}
	} else {
		builder = NewSubsequentEnvelopeTransferChainEntryBuilder(input.PreviousEnvelopeTransferChainEntrySignedContent)
	}

	entry, err := builder.
		WithTransportDocumentChecksum(input.TransportDocumentChecksum).
		WithEBLPlatform(input.EBLPlatform).
		WithTransactions(input.Transactions).
		Build()

	if err != nil {
		return "", WrapEnvelopeError(err, "failed to build transfer chain entry")
	}

	// Step 3: Sign the transfer chain entry with the platform's private key.
	// The keyID is automatically computed inside the Sign method.
	signedContent, err := entry.Sign(privateKey, certChain)
	if err != nil {
		return "", WrapEnvelopeError(err, "failed to sign transfer chain entry")
	}

	return signedContent, nil
}

// CreateTransferTransaction is a helper function to create a TRANSFER transaction.
//
// Parameters:
//   - actor: The party performing the transfer (must be on the sending platform).
//   - recipient: The party receiving the transfer (may be on a different platform).
func CreateTransferTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
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
func CreateIssueTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
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
func CreateEndorseTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
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
func CreateSignTransaction(actor ActorParty) Transaction {
	return Transaction{
		ActionCode:     "SIGN",
		Actor:          actor,
		Recipient:      nil, // SIGN transactions don't have a recipient
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}
