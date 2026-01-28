package pint

// these are the types correpsonding to the API responses for the PINT API (see DCSA EBL_PINT 3.0.0)

// EnvelopeTransferStartedResponse is returned when an envelope transfer is initiated (201 Created).
//
// This response is UNSIGNED. The sending platform must call PUT /v3/envelopes/{ref}/finish-transfer
// to get a signed EnvelopeTransferFinishedResponseSignedContent.
//
// Spec: DCSA EBL_PINT 3.0.0 - EnvelopeTransferStartedResponse schema
type EnvelopeTransferStartedResponse struct {
	// EnvelopeReference is the receiver-generated opaque identifier for this envelope transfer.
	// Used in subsequent API calls (PUT additional-documents, PUT finish-transfer).
	// Max length: 100 characters
	EnvelopeReference string `json:"envelopeReference"`

	// TransportDocumentChecksum is the SHA-256 checksum of the transport document (eBL).
	// Computed on the canonical form of the JSON.
	// Length: exactly 64 hex characters
	TransportDocumentChecksum string `json:"transportDocumentChecksum"`

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 checksum of the last
	// transfer chain entry received.
	// Length: exactly 64 hex characters
	LastEnvelopeTransferChainEntrySignedContentChecksum string `json:"lastEnvelopeTransferChainEntrySignedContentChecksum"`

	// MissingAdditionalDocumentChecksums lists the checksums of additional documents that
	// the receiving platform expects to receive before accepting the envelope transfer.
	// Empty array if no additional documents are required.
	MissingAdditionalDocumentChecksums []string `json:"missingAdditionalDocumentChecksums"`
}
