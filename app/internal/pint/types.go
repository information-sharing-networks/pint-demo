// types.go defines the PINT API request and response types according to DCSA EBL_PINT 3.0.0 specification.
package pint

import "github.com/information-sharing-networks/pint-demo/app/internal/crypto"

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

// EnvelopeTransferFinishedResponse is the payload of the JWS-signed response returned when
// an envelope transfer is finished or rejected.
//
// This response is SIGNED (wrapped in EnvelopeTransferFinishedResponseSignedContent JWS).
// The signature provides non-repudiation.
//
// Spec: DCSA EBL_PINT 3.0.0 - EnvelopeTransferFinishedResponse schema
type EnvelopeTransferFinishedResponse struct {
	// LastEnvelopeTransferChainEntrySignedContentChecksum is the SHA-256 checksum of the last
	// transfer chain entry received.
	// Length: exactly 64 hex characters
	// Required
	LastEnvelopeTransferChainEntrySignedContentChecksum string `json:"lastEnvelopeTransferChainEntrySignedContentChecksum"`

	// ResponseCode indicates the outcome of the envelope transfer.
	// Values: RECE, DUPE, BSIG, BENV, INCD, MDOC, DISE
	// Required
	ResponseCode string `json:"responseCode"`

	// DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent is the JWS-signed last transfer
	// chain entry from the previously accepted envelope transfer.
	// Only present when ResponseCode is DUPE.
	// Optional
	DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent *crypto.EnvelopeTransferChainEntrySignedContent `json:"duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent,omitempty"`

	// Reason is a free-text comment clarifying the result or suggesting follow-up actions.
	// Should be omitted when ResponseCode is RECE.
	// Max length: 255 characters
	// Optional
	Reason string `json:"reason,omitempty"`

	// MissingAdditionalDocumentChecksums lists the checksums of additional documents that
	// the receiving platform believes have not been transferred.
	// Only present when ResponseCode is MDOC.
	// Optional
	MissingAdditionalDocumentChecksums []string `json:"missingAdditionalDocumentChecksums,omitempty"`

	// ReceivedAdditionalDocumentChecksums lists all additional documents received during
	// the envelope transfer (including ones already possessed).
	// Only present when ResponseCode is RECE or DUPE.
	// Optional
	ReceivedAdditionalDocumentChecksums []string `json:"receivedAdditionalDocumentChecksums,omitempty"`
}

// EnvelopeTransferFinishedResponseSignedContent is a JWS compact serialization string
// containing the signed EnvelopeTransferFinishedResponse payload.
//
// Format: base64url(header).base64url(payload).base64url(signature)
// Pattern: ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
//
// Spec: DCSA EBL_PINT 3.0.0 - EnvelopeTransferFinishedResponseSignedContent schema
type EnvelopeTransferFinishedResponseSignedContent string

// ResponseCode constants for EnvelopeTransferFinishedResponse
const (
	// ResponseCodeRECE indicates the envelope transfer was accepted.
	// HTTP status: 200 OK
	ResponseCodeRECE = "RECE"

	// ResponseCodeDUPE indicates this is a duplicate of a previously accepted transfer.
	// HTTP status: 200 OK
	ResponseCodeDUPE = "DUPE"

	// ResponseCodeBSIG indicates a signature-related error (unknown key, expired, etc.).
	// HTTP status: 422 Unprocessable Content
	ResponseCodeBSIG = "BSIG"

	// ResponseCodeBENV indicates the envelope is not acceptable (wrong recipient, invalid action, etc.).
	// HTTP status: 422 Unprocessable Content
	ResponseCodeBENV = "BENV"

	// ResponseCodeINCD indicates an additional document's checksum or size doesn't match.
	// HTTP status: 409 Conflict
	ResponseCodeINCD = "INCD"

	// ResponseCodeMDOC indicates missing additional documents.
	// HTTP status: 409 Conflict
	ResponseCodeMDOC = "MDOC"

	// ResponseCodeDISE indicates a dispute - the envelope contradicts known transfer chain.
	// HTTP status: 409 Conflict
	ResponseCodeDISE = "DISE"
)

