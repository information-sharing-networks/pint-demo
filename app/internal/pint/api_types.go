package pint

// these are the types correpsonding to the API responses for the PINT API (see DCSA EBL_PINT 3.0.0)

// EnvelopeTransferStartedResponse is returned when an envelope transfer is initiated (201 Created).
//
// This response is used when the receiver has additional documents to be transferred.
// The sending platform must call PUT /v3/envelopes/{ref}/finish-transfer
// to get a signed response once all the additional documents have been uploaded.
type EnvelopeTransferStartedResponse struct {

	// EnvelopeReference is the receiver-generated identifier for this envelope transfer.
	// Used in subsequent API calls (PUT additional-documents, PUT finish-transfer).
	// Max length: 100 characters
	EnvelopeReference string `json:"envelopeReference" example:"4TkP5nvgTly0MwFrDxfIkR2rvOjkUIgzibBoKABU"`

	// TransportDocumentChecksum is the SHA-256 checksum of the transport document (eBL).
	// Computed on the canonical form of the JSON.
	TransportDocumentChecksum string `json:"transportDocumentChecksum" example:"583c29ab3e47f2d80899993200d3fbadb9f8a367f3a39f715935c46d7a283006"`

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 checksum of the last
	// transfer chain entry received.
	LastEnvelopeTransferChainEntrySignedContentChecksum string `json:"lastEnvelopeTransferChainEntrySignedContentChecksum" example:"20a0257b313ae08417e07f6555c4ec829a512c083f3ead16b41158018a22abe9"`

	// MissingAdditionalDocumentChecksums lists the checksums of additional documents that
	// the receiving platform expects to receive before accepting the envelope transfer.
	MissingAdditionalDocumentChecksums []string `json:"missingAdditionalDocumentChecksums"`
}

// SignedEnvelopeTransferFinishedResponse is returned when an envelope transfer is accepted or rejected immediately (200 OK).
// This response contains a JWS compact serialization signature (header.payload.signature)
// The payload when decoded contains an EnvelopeTransferFinishedResponse object that summarizes the result of the transfer.
type SignedEnvelopeTransferFinishedResponse struct {

	// EnvelopeTransferFinishedResponseSignedContent is a JWS-signed response returned when
	// an envelope transfer is accepted or rejected.
	SignedContent string `json:"envelopeTransferFinishedResponseSignedContent"  example:"eyJhbGciOiJFZERTQSIsImtpZCI6IjQ0MzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkMzlkM"`
}

// EnvelopeTransferFinishedResponse is the decoded payload of EnvelopeTransferFinishedResponseSignedContent.
//
// This is what gets JWS-signed and included when the transfer is accepted or rejected.
type EnvelopeTransferFinishedResponse struct {

	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 checksum of the last
	// transfer chain entry received.
	LastEnvelopeTransferChainEntrySignedContentChecksum string `json:"lastEnvelopeTransferChainEntrySignedContentChecksum" example:"20a0257b313ae08417e07f6555c4ec829a512c083f3ead16b41158018a22abe9"`

	// ResponseCode indicates the result of the envelope transfer.
	ResponseCode ResponseCode `json:"responseCode" example:"BSIG"`

	// DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent is the last transfer chain entry
	// from the previously accepted envelope transfer.
	// Only included when ResponseCode is DUPE.
	// This is a JWS compact serialization token.
	DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent *string `json:"duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent,omitempty" example:"eyJhbGciOiJFZERTQSIsImtpZCI6IjQ0MzkzNDQ5MzQ0OTM0NDkzNDQ5MzQ0OTM0NDkzNDQ5MzQ0OTM0NDkzNDQ5MzQ0OTM0NDkzNDQ5MzQ0OTM0NDkzNDQ5Mz"`

	// Reason is a free text comment clarifying the result or suggesting follow-up actions.
	// Omitted when ResponseCode is RECE (no additional information needed).
	Reason *string `json:"reason,omitempty" example:"jws.Verify(): invalid key type"`

	// MissingAdditionalDocumentChecksums lists the checksums of additional documents that
	// have not been received by the receiving platform.
	MissingAdditionalDocumentChecksums []string `json:"missingAdditionalDocumentChecksums,omitempty" example:"583c29ab3e47f2d80899993200d3fbadb9f8a367f3a39f715935c46d7a283006"`

	// ReceivedAdditionalDocumentChecksums confirms all additional documents received during
	// the envelope transfer.
	// Included with RECE or DUPE ResponseCode to provide a signed receipt.
	// This includes all additional documents (including ones the receiver already had).
	ReceivedAdditionalDocumentChecksums []string `json:"receivedAdditionalDocumentChecksums,omitempty" example:"123329ab3e47f2d80899993200d3fbadb9f8a367f3a39f715935c46d7a283006"`
}

// ResponseCode represents the result of an envelope transfer operation.
//
//	@enum	RECE,DUPE,BSIG,BENV,INCD,MDOC,DISE
type ResponseCode string

const (
	// ResponseCodeRECE indicates the envelope transfer was accepted
	ResponseCodeRECE ResponseCode = "RECE"

	// ResponseCodeDUPE indicates this is a duplicate of a previously accepted transfer
	ResponseCodeDUPE ResponseCode = "DUPE"

	// ResponseCodeBSIG indicates rejection due to signature issues
	ResponseCodeBSIG ResponseCode = "BSIG"

	// ResponseCodeBENV indicates rejection due to envelope issues
	ResponseCodeBENV ResponseCode = "BENV"

	// ResponseCodeINCD indicates inconclusive document (checksum/size mismatch, not rejected)
	ResponseCodeINCD ResponseCode = "INCD"

	// ResponseCodeMDOC indicates missing additional documents (not rejected)
	ResponseCodeMDOC ResponseCode = "MDOC"

	// ResponseCodeDISE indicates disputed envelope (contradicts transfer chain knowledge)
	ResponseCodeDISE ResponseCode = "DISE"
)
