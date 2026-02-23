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
	"slices"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
	"github.com/information-sharing-networks/pint-demo/app/internal/services"
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

	// partyValidator is used to validate the recipient party exists and is active on the recipient platform
	partyValidator services.PartyValidator
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
	partyValidator services.PartyValidator,
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
		partyValidator: partyValidator,
	}
}

// HandleStartTransfer godoc
//
//	@Summary		Start envelope transfer
//	@Description	Initiates an eBL envelope transfer. The sender provides the transport document (eBL),
//	@Description	signed envelope manifest, and complete transfer chain.
//	@Description
//	@Description	The receiving platform validates signatures, checksums, and transfer chain integrity.
//	@Description
//	@Description	**Success Responses:**
//	@Description
//	@Description	`201 Created` - Transfer started but not yet accepted (unsigned JSON response)
//	@Description	- The envelope transfer is now active
//	@Description	- Additional documents listed in the EnvelopeManifest are required
//	@Description	- Sender must transfer documents, then call "Finish envelope transfer" endpoint
//	@Description	- Only at finish will the transfer be accepted or rejected with a signed response
//	@Description
//	@Description	Retry handling - if the sender retries a transfer that is active but not yet complete
//	@Description	due to outstanding additional documents the receiver will return an unsnigned response with a 201 status code.
//	@Description	The response body will contain the current state of the transfer, including a list of the missing documents.
//	@Description
//	@Description	`200 OK` - Transfer accepted (with signed response)
//	@Description	- No additional documents required, or receiver already has all documents
//	@Description	- The response body contains a JWS (JSON Web Signature) token, where
//	@Description	the payload contains the response details.
//	@Description
//	@Description	The payload includes the `responseCode`: `RECE` (accepted).
//	@Description
//	@Description	Retry handling - if the sender retries a transfer that has already been accepted,
//	@Description	the receiver will return a signed response with a 200 status code and and response code `DUPE`.
//	@Description	The payload is the same structure as the original response, but additionally includes
//	@Description	a `duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent` field which the sender can use
//	@Description	to confirm which transfer was accepted.
//	@Description
//	@Description	**Error Responses**
//	@Description
//	@Description	`422 Unprocessable Entity` indicates the platform has rejected the transfer.
//	@Description	The response body contains a JWS token with `responseCode` of `BSIG` (signature failure)
//	@Description	or `BENV` (envelope validation failure). Details of the error are in the payload of the JWS.
//	@Description
//	@Description	**Trust Level Failures**
//	@Description
//	@Description	This platform enforces a minimum trust level for signatures,
//	@Description	based on the x5c header in the envelope manifest JWS.
//	@Description	- Trust level 1 is the lowest trust level, and means that a JWS
//	@Description	will be accepted even if no x5c header is present.
//	@Description	- Trust level 2 means the JWS must contain a valid certificate,
//	@Description	(Domain Validation (DV) certificates are allowed).
//	@Description	- Trust level 3 is the highest trust level, and means that the JWS must contain a valid Extended Validation (EV)
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
//	@Description	- Do not assume an unsigned error means the transfer was rejected.
//	@Description	- Only determine transfer acceptance/rejection from signed responses.
//	@Description
//	@Description	The sending platform must not rely on the HTTP response status code alone as it is not covered by the signature.
//	@Description	When there is a mismatch between the HTTP response status code
//	@Description	and the `responseCode` in the signed response, the `responseCode` takes precedence.
//
//	@Tags			PINT
//
//	@Param			request	body		ebl.Envelope								true	"eBL envelope containing transport document, signed manifest, and transfer chain - see the schema ebl.EnvelopeManifest definition for details of the expected structure in the signed field"
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
	var envelope ebl.Envelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		pint.RespondWithErrorResponse(w, r, pint.WrapMalformedRequestError(err, "failed to decode envelope JSON"))
		return
	}
	defer r.Body.Close()

	var reason string

	// Step 2. Envelope verification (signature/envelope errors return 422 with a signed response otherwise 500/unsigned response)
	verifiedEnvelope, err := ebl.VerifyEnvelope(ctx, ebl.EnvelopeVerificationInput{
		Envelope:              &envelope,
		RootCAs:               s.x5cCustomRoots,
		KeyProvider:           s.keyManager,
		RecipientPlatformCode: s.platformCode,
	})
	if err != nil {
		var eblErr *ebl.EblError

		if !errors.As(err, &eblErr) || verifiedEnvelope == nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to verify envelope"))
			return
		}
		responseCode := pint.ResponseCode(eblErr.Code())
		reason := "envelope verification failed: " + err.Error()

		signedResponse, err := s.signEnvelopeTransferFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: verifiedEnvelope.LastTransferChainEntrySignedContentChecksum,
			ResponseCode: responseCode,
			Reason:       &reason,
		})
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create signed response"))
			return
		}

		status := http.StatusUnprocessableEntity
		if responseCode == pint.ResponseCodeDISE {
			status = http.StatusConflict
		}

		reqLogger.Warn("Envelope transfer rejected",
			slog.String("response_code", string(responseCode)),
			slog.String("reason", reason),
			slog.String("last_entry_signed_content_checksum", string(verifiedEnvelope.LastTransferChainEntrySignedContentChecksum)),
		)

		pint.RespondWithSignedContent(w, status, signedResponse)
		return
	}

	// this checksum is needed as part of the response payload
	if verifiedEnvelope.LastTransferChainEntrySignedContentChecksum == "" {
		pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to verify envelope - last chain entry signed content checksum is empty"))
		return
	} // unexpected error - the validation code should have set this if the envelope was valid

	reqLogger.Info("Envelope verified successfully",
		slog.String("sender_platform", verifiedEnvelope.SenderPlatform),
		slog.String("recipient_platform", verifiedEnvelope.RecipientPlatform),
		slog.String("transport_document_checksum", string(verifiedEnvelope.TransportDocumentChecksum)),
	)

	// Step 3. Check for transfer chain conflicts (DISE detection)
	// This detects when the same eBL is sent with conflicting transfer chains to the same platform.
	// Note: This cannot detect double-spends across different platforms (requires CTR).
	existingEntries, err := s.queries.GetTransferChainEntriesByTransportDocumentChecksum(ctx, string(verifiedEnvelope.TransportDocumentChecksum))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to check for existing transfer chain"))
		return
	}

	if len(existingEntries) > 0 {
		// Build map of existing checksums by sequence for comparison
		existingChecksums := make(map[int]string)
		for _, entry := range existingEntries {
			existingChecksums[int(entry.Sequence)] = entry.SignedContentPayloadChecksum
		}

		// Check if new chain is consistent with existing entries
		if err := checkTransferChainConsistency(existingChecksums, verifiedEnvelope.TransferChain); err != nil {
			reason = fmt.Sprintf("transfer chain fork detected: %s", err.Error())
			signedResponse, err := s.signEnvelopeTransferFinishedResponse(pint.EnvelopeTransferFinishedResponse{
				LastEnvelopeTransferChainEntrySignedContentChecksum: verifiedEnvelope.LastTransferChainEntrySignedContentChecksum,
				ResponseCode: pint.ResponseCodeDISE,
				Reason:       &reason,
			})
			if err != nil {
				pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create DISE response"))
				return
			}
			reqLogger.Warn("Transfer chain fork detected",
				slog.String("response_code", string(pint.ResponseCodeDISE)),
				slog.String("reason", reason),
				slog.String("transport_document_checksum", string(verifiedEnvelope.TransportDocumentChecksum)),
			)
			pint.RespondWithSignedContent(w, http.StatusConflict, signedResponse)
			return
		}
	}

	// Step 4. See if this transfer was already initiated
	envelopeAlreadyReceived := false

	existingEnvelope, err := s.queries.GetEnvelopeByLastChainEntrySignedContentPayloadChecksum(ctx, string(verifiedEnvelope.LastTransferChainEntrySignedContentPayloadChecksum))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to check for duplicate envelope"))
			return
		}
	} else {
		envelopeAlreadyReceived = true
	}

	// Step 5. Establish the list of missing documents
	// since the handler allows for retries of transfers, some docments may already be received
	additionalDocuments := getAdditionalDocumentList(verifiedEnvelope.Manifest)
	receivedDocumentChecksums := []string{}
	missingDocuments := []additionalDocument{}
	missingDocumentChecksums := []string{}

	if envelopeAlreadyReceived {
		receivedDocumentChecksums, err = s.queries.GetReceivedAdditionalDocumentChecksums(ctx, existingEnvelope.ID)
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to get received documents"))
			return
		}
	}

	for _, doc := range additionalDocuments {
		if !slices.Contains(receivedDocumentChecksums, doc.checksum) {
			missingDocuments = append(missingDocuments, doc)
			missingDocumentChecksums = append(missingDocumentChecksums, doc.checksum)
		}
	}

	// Step 6. Handle retries
	if envelopeAlreadyReceived {
		if len(missingDocuments) == 0 {
			// All documents have already been received and the transfer was accepted - return DUPE/200
			signedResponse, err := s.signEnvelopeTransferFinishedResponse(pint.EnvelopeTransferFinishedResponse{
				LastEnvelopeTransferChainEntrySignedContentChecksum: ebl.TransferChainEntrySignedContentChecksum(existingEnvelope.LastTransferChainEntrySignedContentChecksum),
				ResponseCode: pint.ResponseCodeDUPE,
				DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent: &existingEnvelope.LastTransferChainEntrySignedContent,
				MissingAdditionalDocumentChecksums:                         missingDocumentChecksums,
				ReceivedAdditionalDocumentChecksums:                        &receivedDocumentChecksums,
			})
			if err != nil {
				pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create DUPE response"))
				return
			}
			reqLogger.Warn("Envelope transfer received for previously accepted transfer",
				slog.String("envelope_reference", existingEnvelope.ID.String()),
				slog.String("response_code", string(pint.ResponseCodeDUPE)),
			)

			pint.RespondWithSignedContent(w, http.StatusOK, signedResponse)
			return
		}

		// Documents still missing - return 201 Created (retry of pending transfer)
		response := &pint.EnvelopeTransferStartedResponse{
			EnvelopeReference:                                   existingEnvelope.ID.String(),
			TransportDocumentChecksum:                           ebl.TransportDocumentChecksum(existingEnvelope.TransportDocumentChecksum),
			LastEnvelopeTransferChainEntrySignedContentChecksum: ebl.TransferChainEntrySignedContentChecksum(existingEnvelope.LastTransferChainEntrySignedContentChecksum),
			MissingAdditionalDocumentChecksums:                  missingDocumentChecksums,
		}
		reqLogger.Info("Envelope transfer retry for pending transfer",
			slog.String("envelope_reference", existingEnvelope.ID.String()),
			slog.Int("missing_documents", len(missingDocuments)),
		)
		pint.RespondWithJSONPayload(w, http.StatusCreated, response)
		return
	}

	// the new envelope is structuraly valid and properly signed at this point - now do run-time checks:
	// - is the envelope addressed to this platform?
	// - does the signature comply with this server's minimum trust level policy?
	// - do the parties referenced in the last transfer chain entry exist on this platform?
	// - is the transfer chain consistent with existing entries for this eBL?

	// Step 7. Validate recipient platform matches this server (failures return 422)
	// This prevents a platform from accidentally sending to the wrong platform.
	if verifiedEnvelope.RecipientPlatform != s.platformCode {
		reqLogger.Warn("Transfer intended for different platform",
			slog.String("intended_for", verifiedEnvelope.RecipientPlatform),
			slog.String("this_platform", s.platformCode))

		reason = fmt.Sprintf("envelope does not list the receiving platform as the intended recipient (intended for %s but this server is %s)",
			verifiedEnvelope.RecipientPlatform, s.platformCode)

		signedResponse, err := s.signEnvelopeTransferFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: verifiedEnvelope.LastTransferChainEntrySignedContentChecksum,
			ResponseCode: pint.ResponseCodeBENV,
			Reason:       &reason,
		})
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create signed response"))
			return
		}

		reqLogger.Info("Envelope transfer rejected",
			slog.String("response_code", string(pint.ResponseCodeBENV)),
			slog.String("reason", reason),
			slog.String("last_entry_signed_content_checksum", string(verifiedEnvelope.LastTransferChainEntrySignedContentChecksum)),
		)

		pint.RespondWithSignedContent(w, http.StatusUnprocessableEntity, signedResponse)
		return
	}

	// Step 8. Check trust level meets platform minimum (failures return 422 )
	if verifiedEnvelope.TrustLevel < s.minTrustLevel {

		reason = fmt.Sprintf("Trust level %s does not meet minimum required level (%s)",
			verifiedEnvelope.TrustLevel.String(), s.minTrustLevel.String())

		signedResponse, err := s.signEnvelopeTransferFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: verifiedEnvelope.LastTransferChainEntrySignedContentChecksum,
			ResponseCode: pint.ResponseCodeBSIG,
			Reason:       &reason,
		})
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create signed response"))
			return
		}
		reqLogger.Warn("Trust level too low",
			slog.String("trust_level", verifiedEnvelope.TrustLevel.String()),
			slog.String("min_trust_level", s.minTrustLevel.String()),
			slog.String("reason", reason),
			slog.String("envelope_id", string(verifiedEnvelope.LastTransferChainEntrySignedContentChecksum)),
		)
		pint.RespondWithSignedContent(w, http.StatusUnprocessableEntity, signedResponse)
		return
	}

	// Step 9: Validate the receiving party exists and is active on the recipient platform.

	lastTransferEntry := verifiedEnvelope.LastTransferChainEntry
	lastTransaction := lastTransferEntry.Transactions[len(lastTransferEntry.Transactions)-1]

	recipient := lastTransaction.Recipient

	if reason, err := s.verifyRecipientParty(ctx, recipient); err != nil {
		// if internal error use RespondWithErrorResponse()
		if errors.Is(err, services.ErrPartyNotFound) {
			signedResponse, err := s.signEnvelopeTransferFinishedResponse(pint.EnvelopeTransferFinishedResponse{
				LastEnvelopeTransferChainEntrySignedContentChecksum: verifiedEnvelope.LastTransferChainEntrySignedContentChecksum,
				ResponseCode: pint.ResponseCodeBENV,
				Reason:       &reason,
			})
			if err != nil {
				pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create signed response"))
				return
			}
			reqLogger.Warn("Envelope transfer rejected",
				slog.String("response_code", string(pint.ResponseCodeBENV)),
				slog.String("reason", reason),
				slog.String("last_entry_signed_content_checksum", string(verifiedEnvelope.LastTransferChainEntrySignedContentChecksum)),
			)
			pint.RespondWithSignedContent(w, http.StatusUnprocessableEntity, signedResponse)
			return
		}
		pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to validate party"))
		return
	}

	// Step 10. Start transactional db work
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		logger.ContextWithLogAttrs(ctx,
			slog.String("error", err.Error()),
		)

		pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to begin transaction"))
		return
	}

	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			reqLogger.Error("Failed to rollback transaction",
				slog.String("error", err.Error()),
			)
		}
	}()

	// Step 10. Load transport document if it hasn't been received previously
	txQueries := s.queries.WithTx(tx)
	_, err = txQueries.CreateTransportDocumentIfNew(ctx, database.CreateTransportDocumentIfNewParams{
		Checksum: string(verifiedEnvelope.TransportDocumentChecksum),
		Content:  envelope.TransportDocument,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Transport document already received",
				slog.String("checksum", string(verifiedEnvelope.TransportDocumentChecksum)),
				slog.String("platform_code", s.platformCode),
				slog.String("first_received_from_platform_code", verifiedEnvelope.LastTransferChainEntry.EblPlatform),
			)
		} else {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to store transport document"))
			return
		}
	}

	// Step 11. Create a record of the new envelope transfer if it hasn't been received previously
	lastTransferEntrySignedContent := envelope.EnvelopeTransferChain[len(envelope.EnvelopeTransferChain)-1]

	newEnvelopeRecord, err := txQueries.CreateEnvelope(ctx, database.CreateEnvelopeParams{
		TransportDocumentChecksum: string(verifiedEnvelope.TransportDocumentChecksum),
		ActionCode:                string(lastTransaction.ActionCode),
		SentByPlatformCode:        verifiedEnvelope.LastTransferChainEntry.EblPlatform,
		LastTransferChainEntrySignedContentPayloadChecksum: string(verifiedEnvelope.LastTransferChainEntrySignedContentPayloadChecksum),
		LastTransferChainEntrySignedContentChecksum:        string(verifiedEnvelope.LastTransferChainEntrySignedContentChecksum),
		EnvelopeManifestSignedContent:                      string(envelope.EnvelopeManifestSignedContent),
		LastTransferChainEntrySignedContent:                string(lastTransferEntrySignedContent),
		TrustLevel:                                         int32(verifiedEnvelope.TrustLevel),
	})
	if err != nil {
		pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to store envelope"))
		return
	}

	// Step 12. Create transfer chain entries

	// the transfer chain is a linked list that can grow (e.g. we first receive
	// entries 0-3, now we receive entries 0-5) - use this map so we only append the new items.
	// (otherewise we will get a unique constraint violation)
	existingPayloadChecksums := make(map[string]bool)
	for _, entry := range existingEntries {
		existingPayloadChecksums[entry.SignedContentPayloadChecksum] = true
	}

	for i, entryJWS := range envelope.EnvelopeTransferChain {

		// Compute the JWS checksum (hash of entire JWS string including signature)
		// This is used for chain linking via previous_signed_content_checksum
		entryJWSChecksum, err := crypto.Hash([]byte(entryJWS))
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to calculate entry JWS checksum"))
			return
		}

		// Compute the payload checksum (hash of canonical payload without signature)
		// This is the primary key and is used for duplicate detection
		// The entry has already been parsed and verified in envelope_verification.go
		parsedEntry := verifiedEnvelope.TransferChain[i]
		entryJSON, err := json.Marshal(parsedEntry)
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to marshal entry payload"))
			return
		}

		canonicalPayload, err := crypto.CanonicalizeJSON(entryJSON)
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to canonicalize entry payload"))
			return
		}

		entryPayloadChecksum, err := crypto.Hash(canonicalPayload)
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to calculate entry payload checksum"))
			return
		}

		// Skip if we already have this entry
		if existingPayloadChecksums[entryPayloadChecksum] {
			continue
		}

		// Get previous entry JWS checksum (NULL for first entry)
		var previousJWSChecksum *string
		if i > 0 {
			prevChecksum, err := crypto.Hash([]byte(envelope.EnvelopeTransferChain[i-1]))
			if err != nil {
				pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to calculate previous entry checksum"))
				return
			}
			previousJWSChecksum = &prevChecksum
		}

		// Store the new transfer chain entry
		_, err = txQueries.CreateTransferChainEntry(ctx, database.CreateTransferChainEntryParams{
			SignedContentPayloadChecksum:  entryPayloadChecksum,
			TransportDocumentChecksum:     string(verifiedEnvelope.TransportDocumentChecksum),
			EnvelopeID:                    newEnvelopeRecord.ID,
			SignedContent:                 string(entryJWS),
			SignedContentChecksum:         entryJWSChecksum,
			PreviousSignedContentChecksum: previousJWSChecksum,
			// #nosec G115 -- transfer chains never exceed int32 max
			Sequence: int32(i),
		})
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to store transfer chain entry"))
			return
		}
	}

	// Step 15. Create placeholder records for missing additional documents (where applicable)
	for _, doc := range missingDocuments {
		_, err = txQueries.CreateExpectedAdditionalDocument(ctx, database.CreateExpectedAdditionalDocumentParams{
			EnvelopeID:         newEnvelopeRecord.ID,
			DocumentChecksum:   doc.checksum,
			DocumentName:       doc.name,
			ExpectedSize:       doc.size,
			MediaType:          doc.mediaType,
			IsEblVisualisation: doc.isEblVisualisation,
		})
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create expected additional document record"))
			return
		}
	}

	// Step 16. If no outstanding additional documents, mark envelope as accepted
	if len(missingDocuments) == 0 {
		if err := txQueries.MarkEnvelopeAccepted(ctx, newEnvelopeRecord.ID); err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to mark envelope as accepted"))
			return
		}
	}

	// Commit db changes
	if err := tx.Commit(ctx); err != nil {
		logger.ContextWithLogAttrs(ctx,
			slog.String("error", err.Error()),
		)

		pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to commit transaction"))
		return
	}

	// Step 17. Handle request with no outstanding additional documents (immediate acceptance - 200/RECE)
	if len(missingDocuments) == 0 {
		// Create and sign the RECE response
		receivedDocs := []string{}
		signedResponse, err := s.signEnvelopeTransferFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: verifiedEnvelope.LastTransferChainEntrySignedContentChecksum,
			ResponseCode:                        pint.ResponseCodeRECE,
			ReceivedAdditionalDocumentChecksums: &receivedDocs,
		})
		if err != nil {
			pint.RespondWithErrorResponse(w, r, pint.WrapInternalError(err, "failed to create RECE response"))
			return
		}

		reqLogger.Info("Envelope transfer accepted immediately - no additional documents required",
			slog.String("response_code", "RECE"),
			slog.String("envelope_reference", newEnvelopeRecord.ID.String()),
		)

		pint.RespondWithSignedContent(w, http.StatusOK, signedResponse)
		return
	}

	// Step 18. Return response for pending transfer (201 Created/unsigned response).
	response := &pint.EnvelopeTransferStartedResponse{
		EnvelopeReference:                                   newEnvelopeRecord.ID.String(),
		TransportDocumentChecksum:                           verifiedEnvelope.TransportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: verifiedEnvelope.LastTransferChainEntrySignedContentChecksum,
		MissingAdditionalDocumentChecksums:                  missingDocumentChecksums,
		ReceivedAdditionalDocumentChecksums:                 receivedDocumentChecksums,
	}
	reqLogger.Info("Envelope transfer started pending additional documents",
		slog.String("envelope_reference", newEnvelopeRecord.ID.String()),
		slog.Int("missing_documents", len(missingDocuments)),
	)

	pint.RespondWithJSONPayload(w, http.StatusCreated, response)
}

// signEnvelopeTransferFinishedResponse creates a JWS-signed EnvelopeTransferFinishedResponse.
// This is used for 200/422 (DUPE,RECE & BSIG,BENV) responses.
func (s *StartTransferHandler) signEnvelopeTransferFinishedResponse(response pint.EnvelopeTransferFinishedResponse) (pint.SignedEnvelopeTransferFinishedResponse, error) {
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}

	jws, err := crypto.SignJSON(jsonBytes, s.signingKey, s.x5cCertChain)
	if err != nil {
		return "", fmt.Errorf("failed to sign response: %w", err)
	}

	return pint.SignedEnvelopeTransferFinishedResponse(jws), nil
}

// checkTransferChainConsistency verifies that if we already have a transfer chain for this eBL
// then the new chain is a legitimate extension.
//
// The new chain must contain all existing entries in the same order with matching payload checksums.
// If the new chain is inconsistent then this transfer should be rejected since it is a potential double spend.
//
// Parameters:
//   - existingChecksums: map of sequence position (0-indexed) to payload checksum for existing entries
//   - newChain: the received transfer chain entries to validate
//
// Returns nil if consistent, error describing the conflict if inconsistent.
func checkTransferChainConsistency(
	existingChecksums map[int]string,
	newChain []*ebl.EnvelopeTransferChainEntry,
) error {
	existingChainLength := len(existingChecksums)
	newChainLength := len(newChain)

	// New chain must be at least as long as existing chain (can be longer if extending)
	if newChainLength < existingChainLength {
		return fmt.Errorf("new chain is shorter than existing chain - has %d entries, existing chain has %d entries",
			newChainLength, existingChainLength)
	}

	// Check each existing entry appears in new chain at same position with same payload checksum
	for seq, existingPayloadChecksum := range existingChecksums {
		// Compute payload checksum of new chain entry at this position
		// The entry has already been parsed and verified in envelope_verification.go
		newEntry := newChain[seq]

		// Marshal to JSON and canonicalize
		newEntryJSON, err := json.Marshal(newEntry)
		if err != nil {
			return fmt.Errorf("failed to marshal new chain entry at position %d: %w", seq, err)
		}

		canonicalPayload, err := crypto.CanonicalizeJSON(newEntryJSON)
		if err != nil {
			return fmt.Errorf("failed to canonicalize payload for new chain entry at position %d: %w", seq, err)
		}

		newPayloadChecksum, err := crypto.Hash(canonicalPayload)
		if err != nil {
			return fmt.Errorf("failed to compute payload checksum for new chain entry at position %d: %w", seq, err)
		}

		// If payload checksums don't match, we have a fork
		if newPayloadChecksum != existingPayloadChecksum {
			return fmt.Errorf("fork at position %d: existing entry has payload checksum %s, new entry has payload checksum %s",
				seq, existingPayloadChecksum, newPayloadChecksum)
		}
	}
	// TODO where there has been one or more transfers, we should also check the endorsement chain is consistent
	// (i.e for each transfer chain entry, the endorsee and transfer recipient should be the same party, and
	// the actor of the transfer transaction should be the endorsee of the previous entry).
	// Note there is still a question mark about what counts as being 'the same party' (do all identifying codes for a party need to match etc.)

	return nil
}

// verifyRecipientParty verifies that the recipient party is known and active on the platform.
//
// Senders may provide multiple identifyingCodes for the recipient - each should uniquely
// identify a party, and if multiple codes exist, they must refer to the same legal entity.
// Multiple codes enable different downstream systems to use their preferred identifier
// (e.g., both DID and LEI for the same company).
//
// **Validation Strategy**
// Validate each code via the party validator service and ensure all successfully validated
// codes refer to the same internal party ID.
//
// a. No codes validate = REJECT
// b. Codes validate to different party IDs = REJECT
// c. Some codes validate, others don't = REJECT
// e. All codes validate to same party ID = ACCEPT
//
// TODO: check the expectation for receiver logic:
//   - Rule b is implied by the spec (which says the sender should take care not to send conflicting codes).
//   - Rule c is not explicitly required but seems sensible: accepting unmatched codes
//     risks downstream confusion since there is no way for the downstream system
//     to know which code(s) were successfully validated.
func (s *StartTransferHandler) verifyRecipientParty(ctx context.Context, recipient *ebl.RecipientParty) (reason string, error error) {

	validatedPartyIDs := make(map[string]bool) // partyID -> true
	var unrecognizedCodes []string

	//  see which codes are on the db
	for _, code := range recipient.IdentifyingCodes {
		// convert to PartyIdentifyingCode
		identifyingCode := services.PartyIdentifyingCode{
			CodeListProvider: code.CodeListProvider,
			PartyCode:        code.PartyCode,
			CodeListName:     code.CodeListName,
		}
		partyID, err := s.partyValidator.GetPartyIDByIdentifyingCode(ctx, identifyingCode)
		if err != nil {
			if errors.Is(err, services.ErrPartyNotFound) {
				// Track unrecognized codes
				unrecognizedCodes = append(unrecognizedCodes,
					fmt.Sprintf("%s:%s", code.CodeListProvider, code.PartyCode))
				continue
			}

			// internal error
			return "", fmt.Errorf("failed to validate party: %w", err)
		}

		// Track validated party IDs
		validatedPartyIDs[partyID] = true
	}

	// Reject if no codes validated
	if len(validatedPartyIDs) == 0 {
		reason = fmt.Sprintf("The recipient party <%s> could not be located using the provided identifying codes", recipient.PartyName)
		return reason, services.ErrPartyNotFound
	}

	// Reject if any codes were not recognized
	if len(unrecognizedCodes) > 0 {
		reason = fmt.Sprintf("Could not validate all identifying codes for recipient party <%s>. Unrecognized codes: %v.", recipient.PartyName, unrecognizedCodes)
		return reason, services.ErrPartyNotFound
	}

	// Reject if codes validated to different parties
	if len(validatedPartyIDs) > 1 {
		reason = fmt.Sprintf("Identifying codes for <%s> resolved to multiple different parties", recipient.PartyName)
		return reason, services.ErrPartyNotFound
	}

	return "", nil
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
