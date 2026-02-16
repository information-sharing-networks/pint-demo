package handlers

// transfer_additional_document.go implements the PUT /v3/envelopes/{envelopeReference}/additional-documents/{documentChecksum} endpoint

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// TransferAdditionalDocumentHandler handles PUT /v3/envelopes/{envelopeReference}/additional-documents/{documentChecksum} requests
type TransferAdditionalDocumentHandler struct {
	queries *database.Queries
	pool    *pgxpool.Pool

	// ed25519.PrivateKey or *rsa.PrivateKey used for signing responses to the sender
	signingKey any

	// X.509 certificate chain for signing (optional)
	x5cCertChain []*x509.Certificate
}

// NewTransferAdditionalDocumentHandler creates a new handler for transferring additional documents
func NewTransferAdditionalDocumentHandler(
	queries *database.Queries,
	pool *pgxpool.Pool,
	signingKey any,
	x5cCertChain []*x509.Certificate,
) *TransferAdditionalDocumentHandler {
	return &TransferAdditionalDocumentHandler{
		queries:      queries,
		pool:         pool,
		signingKey:   signingKey,
		x5cCertChain: x5cCertChain,
	}
}

// createSignedFinishedResponse creates a JWS-signed EnvelopeTransferFinishedResponse.
// This is used for 409/422 (INCD & BSIG,BENV) responses.
func (h *TransferAdditionalDocumentHandler) createSignedFinishedResponse(response pint.EnvelopeTransferFinishedResponse) (pint.SignedEnvelopeTransferFinishedResponse, error) {
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}

	jws, err := crypto.SignJSON(jsonBytes, h.signingKey, h.x5cCertChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign response: %w", err)
	}

	return pint.SignedEnvelopeTransferFinishedResponse(jws), nil
}

// HandleTransferAdditionalDocument godoc
//
//	@Summary		Transfer additional documents
//	@Description	Transfer an additional document (supporting document or eBL visualisation) associated with an eBL envelope transfer.
//	@Description
//	@Description	The receiving platform validates:
//	@Description	- Document was declared in the EnvelopeManifest.
//	@Description	- SHA-256 checksum matches the URL parameter.
//	@Description	- Document size matches the manifest.
//	@Description
//	@Description	**Envelope Reference**
//	@Description
//	@Description	The envelope reference is a UUID that identifies the eBL envelope transfer (this is returned
//	@Description	by the start transfer endpoint when the transfer is started)
//	@Description
//	@Description	**Request Body Format**
//	@Description
//	@Description	The request body is a base64-encoded string containing the document content.
//	@Description	Example: `"UmF3IGNvbnRlbnQgb2YgdGhlIGZpbGU..."` (json string containing the base64 document content).
//	@Description
//	@Description	The decoded content type is determined by the sending platform based on the media type
//	@Description	declared in the EnvelopeManifest.
//	@Description
//	@Description	If the sending platform loses track of the transfer state for a document, it can safely
//	@Description	retry the transfer by resending the same document.
//	@Description
//	@Description	If the sending platform loses track of which documents have not been received, it can call
//	@Description	the PUT /v3/envelopes/{envelopeReference} endpoint again to get the current state.
//	@Description
//	@Description	**Success Response:**
//	@Description
//	@Description	`204 No Content` - This is returned when the document is received successfully,
//	@Description	or when the document has already been received.
//	@Description
//	@Description
//	@Description	**Error Responses (signed):**
//	@Description
//	@Description	`409 Conflict` - Checksum or size mismatch (INCD response code).
//	@Description
//	@Description	`422 Unprocessable Entity` - Envelope rejected (BSIG/BENV response code).
//	@Description
//
//	@Tags		PINT
//
//	@Accept		json
//
//	@Param		envelopeReference	path	string	true	"Envelope reference (UUID)"
//	@Param		documentChecksum	path	string	true	"SHA-256 checksum of the document"
//	@Param		body				body	string	true	"Base64-encoded document content (plain string, e.g., UmF3IGNvbnRlbnQ...)"
//
//	@Success	204					"Document received successfully"
//	@Failure	400					{object}	pint.ErrorResponse							"Malformed request"
//	@Failure	404					{object}	pint.ErrorResponse							"Envelope or document not found"
//	@Failure	409					{object}	pint.SignedEnvelopeTransferFinishedResponse	"Checksum/size mismatch (INCD)"
//	@Failure	422					{object}	pint.SignedEnvelopeTransferFinishedResponse	"Envelope rejected (BSIG/BENV)"
//	@Failure	500					{object}	pint.ErrorResponse							"Internal error"
//
//	@Router		/v3/envelopes/{envelopeReference}/additional-documents/{documentChecksum} [put]
func (h *TransferAdditionalDocumentHandler) HandleTransferAdditionalDocument(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqLogger := logger.ContextRequestLogger(ctx)

	// Step 1: Parse URL parameters
	envelopeRefStr := chi.URLParam(r, "envelopeReference")
	documentChecksum := chi.URLParam(r, "documentChecksum")

	if envelopeRefStr == "" || documentChecksum == "" {
		pint.RespondWithError(w, r, pint.NewMalformedRequestError("missing URL parameters"))
		return
	}

	envelopeRef, err := uuid.Parse(envelopeRefStr)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "invalid envelope reference"))
		return
	}

	reqLogger.Info("Transferring additional document",
		slog.String("envelope_reference", envelopeRefStr),
		slog.String("document_checksum", documentChecksum),
	)

	// Step 2: Read and decode base64 request body
	// Note: Request size is already limited by middleware.RequestSizeLimit
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "failed to read request body"))
		return
	}
	defer r.Body.Close()

	// Expect a plain json string with base64-encoded document content
	// unmarshal takes care of JSON string escaping
	var base64Content string
	err = json.Unmarshal(bodyBytes, &base64Content)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "failed to decode base64 content"))
		return
	}

	// Decode the base64 string to get the actual binary document content (PDF, image, etc.)
	documentContent, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "invalid base64 content"))
		return
	}

	if len(documentContent) == 0 {
		pint.RespondWithError(w, r, pint.NewMalformedRequestError("document content is empty"))
		return
	}

	// Step 3: Lookup envelope by reference
	envelope, err := h.queries.GetEnvelopeByReference(ctx, envelopeRef)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			pint.RespondWithError(w, r, pint.NewValidationError("envelope not found"))
			return
		}
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to lookup envelope"))
		return
	}

	// Step 4: Verify envelope is still pending (all documents not yet received)
	// Check if all documents have already been received
	missingDocs, err := h.queries.GetMissingAdditionalDocumentChecksums(ctx, envelope.ID)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to check for missing documents"))
		return
	}

	if len(missingDocs) == 0 {
		reason := "envelope transfer already completed - all documents received"
		signedResponse, err := h.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: envelope.LastTransferChainEntryChecksum,
			ResponseCode: pint.ResponseCodeBENV,
			Reason:       &reason,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create rejection response"))
			return
		}
		pint.RespondWithSignedRejection(w, r, http.StatusUnprocessableEntity, signedResponse, pint.ResponseCodeBENV, reason)
		return
	}

	// Step 5: Lookup expected document in additional_documents table
	expectedDoc, err := h.queries.GetAdditionalDocument(ctx, database.GetAdditionalDocumentParams{
		EnvelopeID:       envelope.ID,
		DocumentChecksum: documentChecksum,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			reason := "unrelated document (document checksum not declared in envelope manifest)"
			signedResponse, err := h.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
				LastEnvelopeTransferChainEntrySignedContentChecksum: envelope.LastTransferChainEntryChecksum,
				ResponseCode: pint.ResponseCodeINCD,
				Reason:       &reason,
			})
			if err != nil {
				pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create rejection response"))
				return
			}
			pint.RespondWithSignedRejection(w, r, http.StatusConflict, signedResponse, pint.ResponseCodeINCD, reason)
			return
		}
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to lookup expected document"))
		return
	}

	// Step 6: Check if document has already been received
	if expectedDoc.ReceivedAt.Valid {
		reqLogger.Warn("Document already received",
			slog.String("received_at", expectedDoc.ReceivedAt.Time.String()),
		)
		// Return 204 to confirm ok - no content change
		pint.RespondWithStatusCodeOnly(w, http.StatusNoContent)
		return
	}

	// Step 7: Compute SHA-256 checksum of the decoded content
	actualChecksum, err := crypto.Hash(documentContent)
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to compute document checksum"))
		return
	}

	// Step 8: Verify checksum matches URL parameter
	if actualChecksum != documentChecksum {
		reason := fmt.Sprintf("document checksum mismatch: expected %s, got %s", documentChecksum, actualChecksum)
		signedResponse, err := h.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: envelope.LastTransferChainEntryChecksum,
			ResponseCode: pint.ResponseCodeINCD,
			Reason:       &reason,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create INCD response"))
			return
		}
		pint.RespondWithSignedRejection(w, r, http.StatusConflict, signedResponse, pint.ResponseCodeINCD, reason)
		return
	}

	// Step 9: Verify document size matches expected size
	actualSize := int64(len(documentContent))
	if actualSize != expectedDoc.ExpectedSize {
		reason := fmt.Sprintf("document size mismatch: expected %d bytes, got %d bytes", expectedDoc.ExpectedSize, actualSize)
		signedResponse, err := h.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: envelope.LastTransferChainEntryChecksum,
			ResponseCode: pint.ResponseCodeINCD,
			Reason:       &reason,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create INCD response"))
			return
		}
		pint.RespondWithSignedRejection(w, r, http.StatusConflict, signedResponse, pint.ResponseCodeINCD, reason)
		return
	}

	// Step 10: Store document content
	err = h.queries.UpdateAdditionalDocumentContent(ctx, database.UpdateAdditionalDocumentContentParams{
		EnvelopeID:       envelope.ID,
		DocumentChecksum: documentChecksum,
		DocumentContent:  documentContent,
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to store document"))
		return
	}

	reqLogger.Info("Additional document received successfully",
		slog.String("document_checksum", documentChecksum),
		slog.Int64("size_bytes", actualSize),
		slog.Bool("is_ebl_visualisation", expectedDoc.IsEblVisualisation),
		slog.String("envelope_reference", envelopeRefStr),
	)

	// Step 11: Return 204 No Content (unsigned response per spec)
	pint.RespondWithStatusCodeOnly(w, http.StatusNoContent)
}
