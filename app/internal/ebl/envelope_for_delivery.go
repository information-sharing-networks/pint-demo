package ebl

// envelope_transfer.go provides the high level functions for creating DCSA EBL_PINT API envelopes for transfer.
//
// For standard usage you should use the high level function in this file, rather than the
// low level functions in envelope.go and transfer_chain.go.
//

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// CreateEnvelopeInput contains the data needed to create a DCSA envelope transfer.
type CreateEnvelopeInput struct {

	// ReceivedEnvelope is the envelope received from another platform (via POST /v3/envelopes)
	ReceivedEnvelope *Envelope

	// NewTransactions is the list of transactions to be added to the transfer chain.
	NewTransactions []Transaction

	// SupportingDocumentFilePaths is an optional list of paths to supporting documents.
	// If provided, each file will be read, checksummed, and metadata included in the envelope manifest.
	// The binary data will be sent separately via the supporting documents API.
	//
	// Note the metadata for the ebl visualization (if provided by the carrier) is propagated automatically
	// from the received envelope and should not be included here.
	SupportingDocumentFilePaths []string
}

// CreateEnvelopeForDelivery prepares a complete envelope ready to send to POST /v3/envelopes.
// Note the caller must have already verified the received envelope before calling this function.
//
// When sending envelopes to a party on another platform:
//  1. Create the relevant transactions using transaction.go helpers (CreateTransferTransaction, CreateEndorseTransaction, etc.)
//  2. retrieve the previously accepted envelope
//  3. collect any supporting docs you want to include in the transfer
//  4. call CreateEnvelopeForDelivery() to create the new envelope
//  5. Marshal and send to next platform via PINT client (POST /v3/envelopes)
//
// Parameters:
//   - input: The data for the envelope transfer (received envelope, new transfer chain entry, optional document metadata)
//   - privateKey: The platform's private key (ed25519.PrivateKey or *rsa.PrivateKey)
//   - certChain: Optional X.509 certificate chain. Pass nil if not needed.
//
// Returns the complete Envelope ready to be JSON-marshaled and sent to POST /v3/envelopes.
func CreateEnvelopeForDelivery(
	input CreateEnvelopeInput,
	privateKey any,
	certChain []*x509.Certificate,
	eBLPlatform string,
) (*Envelope, error) {

	// Step 1: Validate input
	if input.ReceivedEnvelope == nil {
		return nil, NewEnvelopeError("received envelope is required")
	}

	// check the envelope has the required fields
	if err := input.ReceivedEnvelope.ValidateStructure(); err != nil {
		return nil, WrapEnvelopeError(err, "received envelope is invalid")
	}

	if eBLPlatform == "" {
		return nil, NewEnvelopeError("eblPlatform is required")
	}

	// extract the manifest payload
	receivedEnvelopeManifest, err := input.ReceivedEnvelope.EnvelopeManifestSignedContent.Payload()
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to extract received envelope manifest payload")
	}

	// Step 2: Build the complete transfer chain
	// Start with the received envelope's transfer chain (the existing history)
	receivedTransferEntryChain := make([]TransferChainEntrySignedContent, 0, len(input.ReceivedEnvelope.EnvelopeTransferChain)+1)
	receivedTransferEntryChain = append(receivedTransferEntryChain, input.ReceivedEnvelope.EnvelopeTransferChain...)

	// Append the new transfer chain entry if provided
	if len(input.NewTransactions) > 0 {

		// use the tranfer chain entry builder to create the new entry linked to the previous entry
		newEntry, err := NewEnvelopeTransferChainEntryBuilder(false).
			WithTransportDocumentChecksum(receivedEnvelopeManifest.TransportDocumentChecksum).
			WithEBLPlatform(eBLPlatform).
			WithPreviousEnvelopeTransferChainEntrySignedContentChecksum(receivedEnvelopeManifest.LastEnvelopeTransferChainEntrySignedContentChecksum).
			WithTransactions(input.NewTransactions).
			Build()
		if err != nil {
			return nil, WrapEnvelopeError(err, "failed to build new transfer chain entry")
		}
		signedEntry, err := newEntry.Sign(privateKey, certChain)
		if err != nil {
			return nil, WrapEnvelopeError(err, "failed to sign new transfer chain entry")
		}

		receivedTransferEntryChain = append(receivedTransferEntryChain, signedEntry)
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
	lastTransferChainEntry := receivedTransferEntryChain[len(receivedTransferEntryChain)-1]
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
		WithEnvelopeTransferChain(receivedTransferEntryChain).
		Build()

	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to build Envelope")
	}

	return envelope, nil
}
