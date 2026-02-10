package handlers

// start_transfer.go implements the POST /v3/envelopes endpoint for starting envelope transfers.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// additionalDocument represents a document that must be transferred as part of the envelope
type additionalDocument struct {
	checksum           string
	name               string
	size               int64
	mediaType          string
	isEblVisualisation bool
}

// StartTransferHandler handles POST /v3/envelopes requests
type StartTransferHandler struct {
	queries *database.Queries
	pool    *pgxpool.Pool

	// platformCode is the DCSA platform code for this platform (e.g. "WAVE", "CARX", "EDOX")
	platformCode string

	// keyManager contains the public keys used to verify JWS signatures received from other platforms
	keyManager *pint.KeyManager

	// ed25519.PrivateKey or *rsa.PrivateKey used for signing responses to the sender
	signingKey any

	// X.509 certificate chain for signing (optional)
	x5cCertChain []*x509.Certificate

	// Custom root CAs for x5c verification (optional, nil = system roots)
	x5cCustomRoots *x509.CertPool

	// Minimum trust level required for signatures (server config)
	minTrustLevel crypto.TrustLevel
}

// NewStartTransferHandler creates a new handler for starting envelope transfers
func NewStartTransferHandler(
	queries *database.Queries,
	pool *pgxpool.Pool,
	platformCode string,
	keyManager *pint.KeyManager,
	signingKey any,
	x5cCertChain []*x509.Certificate,
	x5cCustomRoots *x509.CertPool,
	minTrustLevel crypto.TrustLevel,
) *StartTransferHandler {
	return &StartTransferHandler{
		queries:        queries,
		pool:           pool,
		platformCode:   platformCode,
		keyManager:     keyManager,
		signingKey:     signingKey,
		x5cCertChain:   x5cCertChain,
		x5cCustomRoots: x5cCustomRoots,
		minTrustLevel:  minTrustLevel,
	}
}

// createSignedFinishedResponse creates a JWS-signed EnvelopeTransferFinishedResponse.
// this is used for 200/422 (DUPE,RECE & BSIG,BENV) responses.
func (s *StartTransferHandler) createSignedFinishedResponse(response pint.EnvelopeTransferFinishedResponse) (*pint.SignedEnvelopeTransferFinishedResponse, error) {
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	jws, err := crypto.SignJSON(jsonBytes, s.signingKey, s.x5cCertChain)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	return &pint.SignedEnvelopeTransferFinishedResponse{
		SignedContent: jws,
	}, nil
}

// respondWithSignedRejection creates and sends a signed rejection response (422 Unprocessable Entity).
//
// The payload in the JWS token is a  DCSA FinshTransferResponse struct that includes the last chain entry
// signed content checksum, response code and reason description
func (s *StartTransferHandler) respondWithSignedRejection(w http.ResponseWriter, r *http.Request, lastChainChecksum string, responseCode pint.ResponseCode, reason string) {
	signedResponse, err := s.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
		LastEnvelopeTransferChainEntrySignedContentChecksum: lastChainChecksum,
		ResponseCode: responseCode,
		Reason:       &reason,
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create signed response"))
		return
	}

	pint.RespondWithPayload(w, http.StatusUnprocessableEntity, signedResponse)
}

// getAdditionalDocumentList extracts a list of all the expected additional document checksums from the manifest
// (visualization and supporting documents).
func getAdditionalDocumentList(manifest *ebl.EnvelopeManifest) []additionalDocument {
	var docs []additionalDocument

	// Add visualization if present
	if manifest.EBLVisualisationByCarrier != nil {
		doc := manifest.EBLVisualisationByCarrier
		docs = append(docs, additionalDocument{
			checksum:           doc.DocumentChecksum,
			name:               doc.Name,
			size:               doc.Size,
			mediaType:          doc.MediaType,
			isEblVisualisation: true,
		})
	}

	// Add all supporting documents
	for _, doc := range manifest.SupportingDocuments {
		docs = append(docs, additionalDocument{
			checksum:           doc.DocumentChecksum,
			name:               doc.Name,
			size:               doc.Size,
			mediaType:          doc.MediaType,
			isEblVisualisation: false,
		})
	}

	return docs
}

// handleRetry checks if this is a retry of an existing transfer and handles it appropriately.
// Returns (true, nil) if the request was handled as a retry, (false, nil) if not a retry, or (false, err) on error.
func (s *StartTransferHandler) handleRetry(ctx context.Context, w http.ResponseWriter, lastChainChecksum string) (bool, error) {
	reqLogger := logger.ContextRequestLogger(ctx)

	exists, err := s.queries.ExistsEnvelopeByLastChainEntryChecksum(ctx, lastChainChecksum)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("failed to check for duplicate envelope: %w", err)
	}
	if !exists {
		return false, nil
	}

	// Retrieve the existing envelope to check its status
	existingEnvelope, err := s.queries.GetEnvelopeByLastChainEntryChecksum(ctx, lastChainChecksum)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve duplicate envelope: %w", err)
	}

	missingChecksums, err := s.queries.GetMissingAdditionalDocumentChecksums(ctx, existingEnvelope.ID)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve missing documents: %w", err)
	}

	receivedChecksums, err := s.queries.GetReceivedAdditionalDocumentChecksums(ctx, existingEnvelope.ID)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve received documents: %w", err)
	}

	if len(missingChecksums) == 0 {
		// Already accepted previously - return DUPE
		signedResponse, err := s.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: lastChainChecksum,
			ResponseCode: pint.ResponseCodeDUPE,
			DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent: &existingEnvelope.LastTransferChainEntrySignedContent,
			MissingAdditionalDocumentChecksums:                         missingChecksums,
			ReceivedAdditionalDocumentChecksums:                        receivedChecksums,
		})
		if err != nil {
			return false, fmt.Errorf("failed to create DUPE response: %w", err)
		}

		pint.RespondWithPayload(w, http.StatusOK, signedResponse)

		reqLogger.Info("Retry of already-accepted envelope (all docs already received)",
			slog.String("last_chain_checksum", lastChainChecksum),
			slog.String("existing_envelope_reference", existingEnvelope.ID.String()),
			slog.Int("received_documents", len(receivedChecksums)),
		)
		return true, nil
	}

	// Documents still missing - return 201 Created (retry of pending transfer)
	response := &pint.EnvelopeTransferStartedResponse{
		EnvelopeReference:                                   existingEnvelope.ID.String(),
		TransportDocumentChecksum:                           existingEnvelope.TransportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: lastChainChecksum,
		MissingAdditionalDocumentChecksums:                  missingChecksums,
	}

	pint.RespondWithPayload(w, http.StatusCreated, response)

	reqLogger.Info("Retry of pending envelope transfer",
		slog.String("last_chain_checksum", lastChainChecksum),
		slog.String("existing_envelope_reference", existingEnvelope.ID.String()),
		slog.Int("missing_documents", len(missingChecksums)),
		slog.Int("received_documents", len(receivedChecksums)),
	)
	return true, nil
}

// / HandleStartTransfer godoc
//
//	@Summary		Start envelope transfer
//	@Description	Initiates an eBL envelope transfer. The sender provides the transport document (eBL),
//	@Description	signed envelope manifest, and complete transfer chain.
//	@Description
//	@Description	The receiving platform validates signatures, checksums, and transfer chain integrity.
//	@Description
//	@Description	**Success Responses:**
//	@Description
//	@Description	`201 Created` - Transfer started but not yet accepted  (unsigned json response)
//	@Description	- The envelope transfer is now active
//	@Description	- Additional documents listed in the EnvelopeManifest are required
//	@Description	- Sender must transfer documents, then call "Finish envelope transfer" endpoint
//	@Description	- Only at finish will the transfer be accepted or rejected with a signed response
//	@Description
//	@Description	Retry handling - if the sender attempts to start a transfer for an eBL that already has an active transfer,
//	@Description	the receiver assumes the sender has lost track of the state of the transfer.
//	@Description	In this case, the request is treated as a retry and the existing envelope
//	@Description	reference and current missing documents are returned with HTTP 201.
//	@Description
//	@Description	`200 OK` - Transfer accepted immediately (with signed response)
//	@Description	- No additional documents required, or receiver already has all documents
//	@Description	- The response body contains a JWS (JSON Web Signature) token, where
//	@Description	the payload contains the response details.
//	@Description
//	@Description	The payload includes the `responseCode`: `RECE` (accepted) or `DUPE` (duplicate).
//	@Description	`DUPE` means this transfer was previously received and accepted - in this case the response
//	@Description	also includes the last accepted transfer chain entry
//	@Description	`duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent` which the sender can use
//	@Description	to confirm which transfer was accepted.
//	@Description
//	@Description	**Error Responses**
//	@Description
//	@Description	`422 Unprocessable Entity` indicates the platform has rejected the transfer.
//	@Description	The response body contains a JWS token with `responseCode` of `BSIG` (signature failure)
//	@Description	or `BENV` (envelope validation failure). Details of the error are in the payload of the JWS.
//	@Description
//	@Description	**Trust Level Failures**
//	@Description	This platform enforces a minimum trust level for signatures,
//	@Description	based on the x5c header in the envelope manifsest JWS.
//	@Description	- Trust level 1 is the lowest trust level, and means that a JWS
//	@Description	will be accepted even if no x5c header is present.
//	@Description	- Trust level 2 means the JWS must contain a valid certificate,
//	@Description	(Domain Validation (DV) certificates are allowed).
//	@Description	- Trust level 3 is the hightest trust level, and means that the JWS must contain a valid Extended Validation (EV)
//	@Description	or Organization Validation (OV) certificate.
//	@Description
//	@Description	The trust level is checked after signature verification, and a valid JWS with an insufficient trust
//	@Description	level will return a `422 Unprocessable Entity` (BSIG) response.
//	@Description
//	@Description	Note that if an x5c cert is included, it must be signed by a trusted root CA and the
//	@Description	public key in the certificate must match the key used to sign the JWS.
//	@Description
//	@Description	**Unsigned Error Responses**
//	@Description
//	@Description	The only time you get an unsigned error response is when the request is malformed or the
//	@Description	receiving platform is having technical difficulties.
//	@Description
//	@Description	`400 Bad Request` indicates a malformed request (invalid JSON, missing required fields, etc.)
//	@Description
//	@Description	`500 Internal Server Error` errors indicate temporary technical issues.
//	@Description	The sender should retry until they receive a signed response.
//	@Description
//	@Description	**Notes**
//	@Description
//	@Description	IMPORTANT: Unsigned responses cannot be verified as originating from the receiving platform
//	@Description	(they may come from middleware or infrastructure). Therefore:
//	@Description	- Do not assume an unsigned error means the transfer was rejected
//	@Description	- only determine transfer acceptance/rejection from signed responses
//	@Description
//	@Description	The sending platform must not rely on the HTTP response status code alone as it is not covered by the signature.
//	@Description	When there is a mismatch between the HTTP response status code
//	@Description	and the `responseCode` in the signed response, the `responseCode` takes precedence.
//
//	@Tags			PINT
//
//	@Param			request	body		ebl.EblEnvelope								true	"eBL envelope containing transport document, signed manifest, and transfer chain - see the schema ebl.EnvelopeManifest definition for details of the expected structure in the signed field"
//	@Param			request	body		ebl.EnvelopeManifest						true	"documentation only (not used directly)"
//	@Param			request	body		ebl.EnvelopeTransferChainEntry				true	"documentation only (not used directly)"
//
//	@Success		200		{object}	pint.SignedEnvelopeTransferFinishedResponse	"Signed response - Transfer accepted immediately (RECE or DUPE) - see the 'default' response for details of the response payload"
//	@Success		201		{object}	pint.EnvelopeTransferStartedResponse		"Transfer started but not yet accepted"
//	@Failure		400		{object}	pint.ErrorResponse							"Malformed request"
//	@Failure		422		{object}	pint.SignedEnvelopeTransferFinishedResponse	"Signed response - Signature or validation failed (BSIG/BENV) - see the 'default' response for details of the response payload"
//	@Failure		500		{object}	pint.ErrorResponse							"Internal error processing request"
//	@Success		default	{object}	pint.EnvelopeTransferFinishedResponse		"documentation only (not returned directly) - decoded payload of the signed response"
//
//	@Router			/v3/envelopes [post]
func (s *StartTransferHandler) HandleStartTransfer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqLogger := logger.ContextRequestLogger(ctx)

	// Step 1. Check json structure (failures return 400, unsigned response)
	var envelope ebl.EblEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "failed to decode envelope JSON"))
		return
	}
	defer r.Body.Close()

	var reason string

	// Step 2. Envelope verification (signature/envelope errors return 422 with a signed response otherwise 500/unsigned response):w
	verificationResult, err := ebl.VerifyEnvelope(ebl.EnvelopeVerificationInput{
		Envelope:              &envelope,
		RootCAs:               s.x5cCustomRoots,
		KeyProvider:           s.keyManager,
		RecipientPlatformCode: s.platformCode,
		Logger:                reqLogger,
	})
	if err != nil {
		var responseCode pint.ResponseCode
		var eblErr *ebl.EblError
		if errors.As(err, &eblErr) {
			switch eblErr.Code() {
			case ebl.ErrCodeSignature:
				responseCode = pint.ResponseCodeBSIG
			case ebl.ErrCodeEnvelope:
				responseCode = pint.ResponseCodeBENV
			}
		}
		if responseCode == "" || verificationResult == nil {
			// internal error
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to verify envelope"))
			return
		}

		lastChainChecksum := verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum
		s.respondWithSignedRejection(w, r, lastChainChecksum, responseCode, err.Error())
		return
	}

	reqLogger.Info("Envelope verified successfully",
		slog.String("sender_platform", verificationResult.SenderPlatform),
		slog.String("recipient_platform", verificationResult.RecipientPlatform),
		slog.String("transport_document_checksum", verificationResult.TransportDocumentChecksum),
		slog.String("last_transfer_chain_checksum", verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum),
	)

	// store the last transfer entry chain checksum for the response.
	// this checksum is a unique identifier for a specific transfer attempt
	// (the last chain entry contains the checksum of the previous entry and the checksum of the transport document,
	//  so it is unique for each transfer attempt)
	lastChainChecksum := verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum
	if lastChainChecksum == "" {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to verify envelope - last chain checksum is empty"))
		return
	} // unexpected error - the validation code should have set this if the envelope was valid

	// Step 3. Validate recipient platform matches this server (failures return 422)
	// This prevents a platform from accidentally sending to the wrong platform.
	if verificationResult.RecipientPlatform != s.platformCode {
		reqLogger.Warn("Transfer intended for different platform",
			slog.String("intended_for", verificationResult.RecipientPlatform),
			slog.String("this_platform", s.platformCode))

		reason = fmt.Sprintf("envelope does not list the receiving platform as the intended recipient (intended for %s but this server is %s)",
			verificationResult.RecipientPlatform, s.platformCode)
		s.respondWithSignedRejection(w, r, lastChainChecksum, pint.ResponseCodeBENV, reason)
		return
	}

	// Step 4. Check trust level meets platform minimum (failures return 422 )
	if verificationResult.TrustLevel < s.minTrustLevel {
		reqLogger.Warn("Trust level too low",
			slog.String("trust_level", verificationResult.TrustLevel.String()),
			slog.String("min_trust_level", s.minTrustLevel.String()))

		reason = fmt.Sprintf("Trust level %s does not meet minimum required level (%s)",
			verificationResult.TrustLevel.String(), s.minTrustLevel.String())
		s.respondWithSignedRejection(w, r, lastChainChecksum, pint.ResponseCodeBSIG, reason)
		return
	}

	// valid envelopes from this point.

	// Step 5. Check for envelope transfer retries
	// The last entry chain checksum is the unique identifier for a specific transfer attempt.
	//
	// retries are handled as follows:
	//	- When there are no additional documents to be transferred return (200 OK,  signed response with a response_code of DUPE)
	// 	- When there are additional documents still to be transferred (201 Created, unsigned response with the current state)
	if handled, err := s.handleRetry(ctx, w, lastChainChecksum); err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to handle retry"))
		return
	} else if handled {
		return
	}

	// Step 6. new transfer received - get the list of expected additional document checksums
	// - if there are additional documents required the transfer can be accepted immediately (response will be 201 Created/RECE)
	// - if there are no additional documents required the response will be 200 OK, and the response will be signed (accepted immediately)

	// Collect all additional documents required for the transfer
	additionalDocs := getAdditionalDocumentList(verificationResult.Manifest)

	// Step 7. TODO check the receiving party exists (not yet implemented)

	// Step 8. start transactional db work
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		logger.ContextWithLogAttrs(ctx,
			slog.String("error", err.Error()),
		)

		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to begin transaction"))
		return
	}

	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			logger.ContextWithLogAttrs(ctx,
				slog.String("error", err.Error()),
			)
		}
	}()

	// Step 9: load transport document if it hasn't been received previously
	txQueries := s.queries.WithTx(tx)
	_, err = txQueries.InsertTransportDocumentIfNew(ctx, database.InsertTransportDocumentIfNewParams{
		Checksum:                      verificationResult.TransportDocumentChecksum,
		Content:                       envelope.TransportDocument,
		FirstReceivedFromPlatformCode: verificationResult.LastTransferChainEntry.EblPlatform,
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to store transport document"))
		return
	}

	// Determine response type: immediate accept (RECE) if no additional docs needed, otherwise pending (NULL)
	var responseCode *string
	if len(additionalDocs) == 0 {
		rece := string(pint.ResponseCodeRECE)
		responseCode = &rece
	}

	// Step 10: Create a record of the envelope transfer
	lastTransferEntry := envelope.EnvelopeTransferChain[len(envelope.EnvelopeTransferChain)-1]

	storedEnvelope, err := txQueries.CreateEnvelope(ctx, database.CreateEnvelopeParams{
		TransportDocumentChecksum:           verificationResult.TransportDocumentChecksum,
		SentByPlatformCode:                  verificationResult.LastTransferChainEntry.EblPlatform,
		LastTransferChainEntryChecksum:      verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum,
		EnvelopeManifestSignedContent:       string(envelope.EnvelopeManifestSignedContent),
		LastTransferChainEntrySignedContent: string(lastTransferEntry),
		ResponseCode:                        responseCode, // RECE if immediate accept, NULL if pending
		ResponseReason:                      nil,
		TrustLevel:                          int32(verificationResult.TrustLevel),
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to store envelope"))
		return
	}

	// Step 11. Create transfer chain entries
	for i, entryJWS := range envelope.EnvelopeTransferChain {

		entryChecksum, err := crypto.Hash([]byte(entryJWS))
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to calculate entry checksum"))
			return
		}

		// Get previous entry checksum (NULL for first entry)
		var previousChecksum *string
		if i > 0 {
			prevChecksum, err := crypto.Hash([]byte(envelope.EnvelopeTransferChain[i-1]))
			if err != nil {
				pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to calculate previous entry checksum"))
				return
			}
			previousChecksum = &prevChecksum
		}

		// store the transfer chain entry
		_, err = txQueries.CreateTransferChainEntry(ctx, database.CreateTransferChainEntryParams{
			TransportDocumentChecksum: verificationResult.TransportDocumentChecksum,
			EnvelopeID:                storedEnvelope.ID,
			SignedContent:             string(entryJWS),
			EntryChecksum:             entryChecksum,
			PreviousEntryChecksum:     previousChecksum,
			// #nosec G115 -- transfer chains never exceed int32 max
			Sequence: int32(i),
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to store transfer chain entry"))
			return
		}
	}

	// Step 11 placeholder records for expected additional documents (where applicable)
	for _, doc := range additionalDocs {
		_, err = txQueries.CreateExpectedAdditionalDocument(ctx, database.CreateExpectedAdditionalDocumentParams{
			EnvelopeID:         storedEnvelope.ID,
			DocumentChecksum:   doc.checksum,
			DocumentName:       doc.name,
			ExpectedSize:       doc.size,
			MediaType:          doc.mediaType,
			IsEblVisualisation: doc.isEblVisualisation,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create expected additional document record"))
			return
		}
	}

	// commit db changes
	if err := tx.Commit(ctx); err != nil {
		logger.ContextWithLogAttrs(ctx,
			slog.String("error", err.Error()),
		)

		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to commit transaction"))
		return
	}

	// Step 12 - handle request with no additional documents (immediate acceptance - 200/RECE)
	if len(additionalDocs) == 0 {
		// Create and sign the RECE response
		signedResponse, err := s.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: lastChainChecksum,
			ResponseCode:                        pint.ResponseCodeRECE,
			ReceivedAdditionalDocumentChecksums: []string{},
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create RECE response"))
			return
		}

		reqLogger.Info("Envelope transfer accepted immediately - no additional documents required",
			slog.String("response_code", "RECE"),
			slog.String("envelope_reference", storedEnvelope.ID.String()),
			slog.String("transport_document_checksum", verificationResult.TransportDocumentChecksum),
			slog.String("last_transfer_chain_entry_checksum", lastChainChecksum),
		)

		pint.RespondWithPayload(w, http.StatusOK, signedResponse)
		return
	}

	// Step 13. Return response for pending transfer (201 Created/ unsigned response)
	// because this is the start of the transfer all the additional docs are 'missing'
	missingChecksums := make([]string, len(additionalDocs))
	for i, doc := range additionalDocs {
		missingChecksums[i] = doc.checksum
	}

	response := &pint.EnvelopeTransferStartedResponse{
		EnvelopeReference:                                   storedEnvelope.ID.String(),
		TransportDocumentChecksum:                           verificationResult.TransportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum,
		MissingAdditionalDocumentChecksums:                  missingChecksums,
	}
	reqLogger.Info("Envelope transfer started pending additional documents",
		slog.String("envelope_reference", storedEnvelope.ID.String()),
		slog.String("transport_document_checksum", verificationResult.TransportDocumentChecksum),
		slog.String("last_transfer_chain_entry_checksum", lastChainChecksum),
		slog.Int("missing_additional_documents", len(missingChecksums)),
	)

	pint.RespondWithPayload(w, http.StatusCreated, response)
}
