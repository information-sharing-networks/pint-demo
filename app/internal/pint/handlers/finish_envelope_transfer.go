package handlers

// finish_envelope_transfer.go implements the PUT /v3/envelopes/{envelopeReference}/finish-transfer endpoint

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FinishEnvelopeTransferHandler handles PUT /v3/envelopes/{envelopeReference}/finish-transfer requests
type FinishEnvelopeTransferHandler struct {
	queries *database.Queries
	pool    *pgxpool.Pool

	// ed25519.PrivateKey or *rsa.PrivateKey used for signing responses to the sender
	signingKey any

	// X.509 certificate chain for signing (optional)
	x5cCertChain []*x509.Certificate
}

// NewFinishEnvelopeTransferHandler creates a new handler for finishing envelope transfers
func NewFinishEnvelopeTransferHandler(
	queries *database.Queries,
	pool *pgxpool.Pool,
	signingKey any,
	x5cCertChain []*x509.Certificate,
) *FinishEnvelopeTransferHandler {
	return &FinishEnvelopeTransferHandler{
		queries:      queries,
		pool:         pool,
		signingKey:   signingKey,
		x5cCertChain: x5cCertChain,
	}
}

// createSignedFinishedResponse creates a JWS-signed EnvelopeTransferFinishedResponse.
// this is used for 200/409/422 (RECE,DUPE,MDOC,DISE & BSIG,BENV) responses.
func (h *FinishEnvelopeTransferHandler) createSignedFinishedResponse(response pint.EnvelopeTransferFinishedResponse) (*pint.SignedEnvelopeTransferFinishedResponse, error) {
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	jws, err := crypto.SignJSON(jsonBytes, h.signingKey, h.x5cCertChain)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	return &pint.SignedEnvelopeTransferFinishedResponse{
		SignedContent: jws,
	}, nil
}

// HandleFinishEnvelopeTransfer godoc
//
//	@Summary		Finish envelope transfer
//	@Description	Use this endpoint after you have finished transferring all additional documents.
//	@Description
//	@Description	Prior to accepting envelope transfer, the receiving platform ensures that all supporting documents listed in the envelope manifest have been successfully transferred.
//	@Description
//	@Description	**Success Responses**
//	@Description
//	@Description	`200 OK` - Transfer accepted (RECE)
//	@Description
//	@Description	All additional documents have been received and the envelope transfer has been accepted on the platform.
//	@Description
//	@Description	The payload of the signed response contains the last transfer chain entry checksum and a list of all received additional document checksums.
//	@Description	(See the `default` response for details of the response payload)
//	@Description
//	@Description	**retry handling:**
//	@Description	when the sender retries a transfer that has already been accepted, the receiver will return a signed response and
//	@Description	the payload will contain a struture identical to the original response, but with a response code of DUPE
//	@Description	and an extra field: duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent.
//	@Description
//	@Description	**Notes**
//	@Description
//	@Description	**Error Responses (signed)**
//	@Description
//	@Description	`409 Conflict` - Missing documents (MDOC) or disputed envelope (DISE) (signed response)
//	@Description	- MDOC: One or more additional documents are still missing (see missingAdditionalDocumentChecksums in response payload)
//	@Description	- DISE: Envelope contradicts transfer chain knowledge (not yet implemented)
//	@Description
//	@Description	`422 Unprocessable Entity` - Envelope rejected (BSIG/BENV) (signed response)
//	@Description	- BSIG: Signature validation failed
//	@Description	- BENV: Envelope validation failed
//	@Description
//	@Description	see the `default` response for details of the response payload
//	@Description
//	@Description	**Error Responses (unsigned)**
//	@Description
//	@Description	`400 Bad Request` - Malformed request - returned as an unsigned error response
//	@Description	`500 Internal Server Error` - Internal error - returned as an unsigned error response
//	@Description
//	@Description	**Note** unsigned responses cannot be verified as originating from the receiving platform -
//	@Description	do not assume an unsigned error response means the transfer was rejected.
//	@Description	Only determine transfer acceptance/rejection from signed responses.
//	@Description
//	@Param		envelopeReference	path		string										true	"Envelope reference (UUID)"
//
//	@Success	200					{object}	pint.SignedEnvelopeTransferFinishedResponse	"Signed response - Transfer accepted (RECE/DUPE)"
//	@Failure	409					{object}	pint.SignedEnvelopeTransferFinishedResponse	"Signed response - Missing documents (MDOC) or disputed (DISE)"
//	@Failure	422					{object}	pint.SignedEnvelopeTransferFinishedResponse	"Signed response - Envelope rejected (BSIG/BENV)"
//	@Failure	500					{object}	pint.ErrorResponse							"Internal error processing request"
//	@Success	default				{object}	pint.EnvelopeTransferFinishedResponse		"documentation only (not returned directly) - decoded payload of the signed response"
//
//	@Tags		PINT
//
//	@Accept		json
//
//	@Router		/v3/envelopes/{envelopeReference}/finish-transfer [put]
func (h *FinishEnvelopeTransferHandler) HandleFinishEnvelopeTransfer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqLogger := logger.ContextRequestLogger(ctx)

	// Step 1: Parse URL parameters
	envelopeRefStr := chi.URLParam(r, "envelopeReference")

	if envelopeRefStr == "" {
		pint.RespondWithError(w, r, pint.NewMalformedRequestError("missing envelopeReference URL parameter"))
		return
	}

	envelopeRef, err := uuid.Parse(envelopeRefStr)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "invalid envelopeReference format"))
		return
	}

	reqLogger.Info("Finish envelope transfer request",
		slog.String("envelope_reference", envelopeRef.String()),
	)

	// Step 2: Retrieve envelope from database
	envelope, err := h.queries.GetEnvelopeByReference(ctx, envelopeRef)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			pint.RespondWithError(w, r, pint.NewMalformedRequestError("envelope not found"))
			return
		}
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to retrieve envelope"))
		return
	}

	// Step 3: Check if all additional documents have been received
	missingDocs, err := h.queries.GetMissingAdditionalDocumentChecksums(ctx, envelope.ID)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to check missing documents"))
		return
	}

	// Step 4: If documents are missing, return MDOC response
	if len(missingDocs) > 0 {
		reqLogger.Warn("Cannot finish transfer - missing documents",
			slog.Int("missing_count", len(missingDocs)),
			slog.Any("missing_checksums", missingDocs),
		)

		reason := fmt.Sprintf("cannot accept envelope transfer: %d additional document(s) not yet received", len(missingDocs))

		signedResponse, err := h.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: envelope.LastTransferChainEntryChecksum,
			ResponseCode:                       pint.ResponseCodeMDOC,
			Reason:                             &reason,
			MissingAdditionalDocumentChecksums: missingDocs,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create MDOC response"))
			return
		}

		pint.RespondWithPayload(w, http.StatusConflict, signedResponse)
		return
	}

	// Step 5: All documents received - get received documents list
	receivedDocs, err := h.queries.GetReceivedAdditionalDocumentChecksums(ctx, envelope.ID)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to get received documents"))
		return
	}

	// Step 6: Check if envelope has already been accepted (DUPE case)
	// If response_code is already RECE, this is a duplicate finish-transfer request
	if envelope.ResponseCode != nil && *envelope.ResponseCode == string(pint.ResponseCodeRECE) {
		reqLogger.Info("Envelope transfer already accepted, returning DUPE")

		signedResponse, err := h.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: envelope.LastTransferChainEntryChecksum,
			ResponseCode: pint.ResponseCodeDUPE,
			DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent: &envelope.LastTransferChainEntrySignedContent,
			ReceivedAdditionalDocumentChecksums:                        receivedDocs,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create DUPE response"))
			return
		}

		pint.RespondWithPayload(w, http.StatusOK, signedResponse)
		return
	}

	// Step 7: Update envelope response code to RECE (acceptance)
	receCode := string(pint.ResponseCodeRECE)
	err = h.queries.UpdateEnvelopeResponse(ctx, database.UpdateEnvelopeResponseParams{
		ID:             envelope.ID,
		ResponseCode:   &receCode,
		ResponseReason: nil,
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to update envelope response"))
		return
	}

	reqLogger.Info("Envelope transfer accepted",
		slog.String("response_code", "RECE"),
		slog.Int("received_documents", len(receivedDocs)),
	)

	// Step 8: Create and return signed RECE response
	signedResponse, err := h.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
		LastEnvelopeTransferChainEntrySignedContentChecksum: envelope.LastTransferChainEntryChecksum,
		ResponseCode:                        pint.ResponseCodeRECE,
		ReceivedAdditionalDocumentChecksums: receivedDocs,
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create RECE response"))
		return
	}

	pint.RespondWithPayload(w, http.StatusOK, signedResponse)
}
