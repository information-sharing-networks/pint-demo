package ebl

// envelope_transfer.go provides the high level functions for creating DCSA EBL_PINT API envelopes.
//
// For standard usage you should use the high level functions in this file, rather than the
// low level functions in envelope.go and transfer_chain.go.
//
// When forwarding envelopes to other platforms (via PINT client):
//  1. Create transactions using helpers (CreateTransferTransaction, CreateEndorseTransaction, etc.)
//  2. Package transactions into a transfer chain entry: CreateTransferChainEntry()
//  3. Create envelope with the new entry: CreateEnvelope()
//  4. Marshal and send to next platform via PINT client (POST /v3/envelopes)
//

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CreateEnvelopeInput contains the data needed to create a DCSA envelope transfer.
type CreateEnvelopeInput struct {

	// ReceivedEnvelope is the envelope received from another platform (via POST /v3/envelopes)
	ReceivedEnvelope *Envelope

	// NewTransferChainEntrySignedContent is the new entry including the transactions to be added to the transfer chain.
	// created by CreateTransferChainEntry()
	// This is optional to support testing where it is useful to be able to recreate an envelope without changing the transfer chain.
	NewTransferChainEntrySignedContent *EnvelopeTransferChainEntrySignedContent

	// SupportingDocumentFilePaths is an optional list of paths to supporting documents.
	// If provided, each file will be read, checksummed, and metadata included in the envelope manifest.
	// The binary data will be sent separately via the supporting documents API.
	//
	// Note the metadata for the ebl visualization (if provided by the carrier) is propagated automatically
	// from the received envelope and should not be included here.
	SupportingDocumentFilePaths []string
}

// CreateEnvelope prepares a complete envelope ready to send to POST /v3/envelopes.
//
// Parameters:
//   - input: The data for the envelope transfer (received envelope, new transfer chain entry, optional document metadata)
//   - privateKey: The platform's private key (ed25519.PrivateKey or *rsa.PrivateKey)
//   - certChain: Optional X.509 certificate chain. Pass nil if not needed.
//
// Returns the complete Envelope ready to be JSON-marshaled and sent to POST /v3/envelopes.
func CreateEnvelope(
	input CreateEnvelopeInput,
	privateKey any,
	certChain []*x509.Certificate,
) (*Envelope, error) {

	// Step 1: Validate input
	if input.ReceivedEnvelope == nil {
		return nil, NewEnvelopeError("received envelope is required")
	}

	// check the envelope has the required fields
	if err := input.ReceivedEnvelope.ValidateStructure(); err != nil {
		return nil, WrapEnvelopeError(err, "received envelope is invalid")
	}

	// Step 2: Build the complete transfer chain
	// Start with the received envelope's transfer chain (the existing history)
	transferChain := make([]EnvelopeTransferChainEntrySignedContent, 0, len(input.ReceivedEnvelope.EnvelopeTransferChain)+1)
	transferChain = append(transferChain, input.ReceivedEnvelope.EnvelopeTransferChain...)

	// Append the new transfer chain entry if provided
	if input.NewTransferChainEntrySignedContent != nil {
		transferChain = append(transferChain, *input.NewTransferChainEntrySignedContent)
	}

	// Step 3: Extract eBL visualization metadata from the received envelope's manifest
	// We parse the received manifest to extract the visualization metadata and automatically propagate it.
	// The EBLVisualizationFilePath is only used for initial issuance (when there's no received envelope manifest).
	var eblVisualizationMetadata *DocumentMetadata

	// extract the eBL visualization from the manifest
	// We don't verify the signature here because the envelope was already verified when received
	parts := strings.Split(string(input.ReceivedEnvelope.EnvelopeManifestSignedContent), ".")
	if len(parts) != 3 {
		return nil, NewEnvelopeError(fmt.Sprintf("invalid JWS format: expected 3 parts, got %d", len(parts)))
	}

	manifestPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to decode manifest JWS payload")
	}

	var receivedManifest EnvelopeManifest
	if err := json.Unmarshal(manifestPayload, &receivedManifest); err != nil {
		return nil, WrapEnvelopeError(err, "failed to unmarshal received envelope manifest")
	}

	// If the received envelope has eBL visualization, propagate it unchanged
	if receivedManifest.EBLVisualisationByCarrier != nil {
		eblVisualizationMetadata = receivedManifest.EBLVisualisationByCarrier
	}

	// Step 4: read any supporting documents and create metadata
	var supportingDocumentsMetadata []DocumentMetadata
	if len(input.SupportingDocumentFilePaths) > 0 {
		supportingDocumentsMetadata = make([]DocumentMetadata, 0, len(input.SupportingDocumentFilePaths))
		for i, filePath := range input.SupportingDocumentFilePaths {
			metadata, err := documentMetadataFromFile(filePath)
			if err != nil {
				return nil, WrapEnvelopeError(err, fmt.Sprintf("failed to load supporting document %d (%s)", i, filePath))
			}
			supportingDocumentsMetadata = append(supportingDocumentsMetadata, *metadata)
		}
	}

	// Step 5: Build the envelope manifest
	lastTransferChainEntry := transferChain[len(transferChain)-1]
	transportDocument := input.ReceivedEnvelope.TransportDocument

	manifestBuilder := NewEnvelopeManifestBuilder().
		WithTransportDocument(transportDocument).
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

	// Step 7: Build the complete Envelope
	envelope, err := NewEnvelopeBuilder().
		WithTransportDocument(transportDocument).
		WithEnvelopeManifestSignedContent(envelopeManifestSignedContent).
		WithEnvelopeTransferChain(transferChain).
		Build()

	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to build Envelope")
	}

	return envelope, nil
}

// CreateTransferChainEntry creates a new signed transfer chain entry for a received envelope.
//
// Use this after you've created one or more transactions (TRANSFER, ENDORSE, etc.) and are
// ready to package them into a transfer chain entry.
//
// This function automatically:
// - Extracts the transport document checksum from the received envelope
// - Links to the previous transfer chain entry
// - Creates and signs the new entry
//
// Parameters:
//   - receivedEnvelope: The envelope received from another platform (via POST /v3/envelopes)
//   - transactions: The transactions to include in the new entry
//   - platformCode: Your platform's code (e.g., "WAVE", "BOLE")
//   - privateKey: Your platform's private key for signing
//   - certChain: Optional X.509 certificate chain
//
// Note you must verify the received envelope before calling this function (this is handled automatically by the POST /v3/envelopes handler)
//
// Returns the signed transfer chain entry ready to use with CreateEnvelope().
func CreateTransferChainEntry(
	receivedEnvelope *Envelope,
	transactions []Transaction,
	platformCode string,
	privateKey any,
	certChain []*x509.Certificate,
) (EnvelopeTransferChainEntrySignedContent, error) {

	// Validate input
	if receivedEnvelope == nil {
		return "", NewEnvelopeError("received envelope is required")
	}
	if len(transactions) == 0 {
		return "", NewEnvelopeError("at least one transaction is required")
	}
	if platformCode == "" {
		return "", NewEnvelopeError("platform code is required")
	}

	// Extract the transport document checksum from the received envelope's manifest
	// We parse the JWS to get the payload without verifying the signature
	// (the envelope was already verified when it was received)
	parts := strings.Split(string(receivedEnvelope.EnvelopeManifestSignedContent), ".")
	if len(parts) != 3 {
		return "", NewEnvelopeError(fmt.Sprintf("invalid JWS format: expected 3 parts, got %d", len(parts)))
	}

	manifestPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", WrapEnvelopeError(err, "failed to decode JWS payload")
	}

	var receivedManifest EnvelopeManifest
	if err := json.Unmarshal(manifestPayload, &receivedManifest); err != nil {
		return "", WrapEnvelopeError(err, "failed to unmarshal received envelope manifest")
	}

	transportDocumentChecksum := receivedManifest.TransportDocumentChecksum

	// Get the last entry from the received transfer chain
	lastEntry := receivedEnvelope.EnvelopeTransferChain[len(receivedEnvelope.EnvelopeTransferChain)-1]

	// Create the new transfer chain entry
	newEntryInput := TransferChainEntryInput{
		TransportDocumentChecksum: transportDocumentChecksum,
		EBLPlatform:               platformCode,
		IsFirstEntry:              false,
		PreviousEnvelopeTransferChainEntrySignedContent: lastEntry,
		Transactions: transactions,
	}

	// Sign the new transfer chain entry
	signedNewEntry, err := createTransferChainEntrySignedContent(newEntryInput, privateKey, certChain)
	if err != nil {
		return "", WrapEnvelopeError(err, "failed to create new transfer chain entry")
	}

	return signedNewEntry, nil
}

// CreateIssueTransaction creates an ISSUE transaction.
//
// This is used in when the carrier issues the eBL to the recipient (shipper).
//
// Returns a Transaction ready to include in the first transfer chain entry.
func CreateIssueTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
		ActionCode:     ActionCodeIssue,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateTransferTransaction creates a TRANSFER transaction.
//
// This is used when the actor transfers the eBL to another party. The recipient may be
// on another platform.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateTransferTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
		ActionCode:     ActionCodeTransfer,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateEndorseTransaction creates an ENDORSE transaction.
//
// This is used when the actor endorses the eBL to a named party.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateEndorseTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
		ActionCode:     ActionCodeEndorse,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateEndorseToOrderTransaction creates an ENDORSE_TO_ORDER transaction.
//
// This is used when the actor endorses the document to order of the recipient, allowing the recipient to further endorse the eBL to another party)
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateEndorseToOrderTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
		ActionCode:     ActionCodeEndorseToOrder,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateBlankEndorseTransaction creates a BLANK_ENDORSE transaction.
//
// This is used when the actor endorses the document without specifying a named endorsee.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateBlankEndorseTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
		ActionCode:     ActionCodeBlankEndorse,
		Actor:          actor,
		Recipient:      nil,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateSignTransaction creates a SIGN transaction.
//
// This is used when a party signs the eBL while in their possession (no recipient).
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSignTransaction(actor ActorParty) Transaction {
	return Transaction{
		ActionCode:     ActionCodeSign,
		Actor:          actor,
		Recipient:      nil, // SIGN transactions don't have a recipient
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// CreateSurrenderForAmendmentTransaction creates a SURRENDER_FOR_AMENDMENT transaction.
//
// This is used when the actor surrenders the eBL for amendment.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSurrenderForAmendmentTransaction(actor ActorParty, recipient RecipientParty, reasonCode SurrenderForAmendmentReasonCode) Transaction {
	return Transaction{
		ActionCode:     ActionCodeSurrenderForAmendment,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		ReasonCode:     &reasonCode,
	}
}

// CreateSurrenderForDeliveryTransaction creates a SURRENDER_FOR_DELIVERY transaction.
//
// This is used when the actor surrenders the eBL for delivery.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSurrenderForDeliveryTransaction(actor ActorParty, recipient RecipientParty) Transaction {
	return Transaction{
		ActionCode:     ActionCodeSurrenderForDelivery,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}
