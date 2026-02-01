package handlers

// start_transfer.go implements the POST /v3/envelopes endpoint for starting envelope transfers.

import (
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

// StartTransferHandler handles POST /v3/envelopes requests
type StartTransferHandler struct {
	queries *database.Queries
	pool    *pgxpool.Pool

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
	keyManager *pint.KeyManager,
	signingKey any,
	x5cCertChain []*x509.Certificate,
	x5cCustomRoots *x509.CertPool,
	minTrustLevel crypto.TrustLevel,
) *StartTransferHandler {
	return &StartTransferHandler{
		queries:        queries,
		pool:           pool,
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
//	@Description	`201 Created` - Transfer started but not yet accepted
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
//	@Description	The only time you get an unsigned response is when the request is malformed or the
//	@Description	receiving platform is having technical difficulties.
//	@Description
//	@Description	`400 Bad Request` indicates a malformed request (invalid JSON, missing required fields, etc.)
//	@Description
//	@Description	`500 Internal Server Error` or other unexpected errors indicate temporary technical issues.
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

	// Step 1. Check envelope structure (failures return 400, unsigned response)
	var envelope ebl.EblEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "failed to decode envelope JSON"))
		return
	}
	defer r.Body.Close()

	verified := false
	trusted := false

	// Step 2. Verify envelope signatures, checksums, and chain integrity (failures return 422 with signed response)
	verificationResult, verificationErr := ebl.VerifyEnvelopeTransfer(ebl.EnvelopeVerificationInput{
		Envelope:    &envelope,
		RootCAs:     s.x5cCustomRoots,
		KeyProvider: s.keyManager,
	})
	if verificationErr == nil {
		verified = true
	}

	// Step 3. Check trust level meets platform minimum (failures return 422 )
	if verified && verificationResult.TrustLevel >= s.minTrustLevel {
		trusted = true
	}

	// Return BSIG or BENV response for a verification or trust level failure
	if !verified || !trusted {

		// Extract the last chain checksum from the envelope for the signed response
		var lastChainChecksum string
		if len(envelope.EnvelopeTransferChain) > 0 {
			lastEntryJWS := envelope.EnvelopeTransferChain[len(envelope.EnvelopeTransferChain)-1]
			lastChainChecksum, _ = crypto.Hash([]byte(lastEntryJWS))
		}

		// Determine response code and reason based on failure type
		var responseCode pint.ResponseCode
		var reason string

		if !verified {
			// Signature or envelope validation failed
			reason = verificationErr.Error()
			responseCode = pint.ResponseCodeBENV // Default to envelope validation error

			var cryptoErr *crypto.CryptoError
			if errors.As(verificationErr, &cryptoErr) {
				if cryptoErr.Code() == crypto.ErrCodeInvalidSignature || cryptoErr.Code() == crypto.ErrCodeCertificate {
					responseCode = pint.ResponseCodeBSIG
				}
			}

			reqLogger.Warn("Envelope verification failed",
				slog.String("response_code", string(responseCode)),
				slog.String("error", verificationErr.Error()),
			)
		} else if !trusted {
			reason = fmt.Sprintf("Trust level %s does not meet minimum required level (%s)",
				verificationResult.TrustLevel.String(), s.minTrustLevel.String())
			responseCode = pint.ResponseCodeBSIG

			reqLogger.Warn("Trust level insufficient",
				slog.String("response_code", string(responseCode)),
				slog.String("trust_level", verificationResult.TrustLevel.String()),
				slog.String("min_trust_level", s.minTrustLevel.String()),
			)
		}

		// Create and sign the rejection response
		signedResponse, err := s.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: lastChainChecksum,
			ResponseCode: responseCode,
			Reason:       &reason,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create rejection response"))
			return
		}

		reqLogger.Info("Request Rejected:",
			slog.String("response_code", string(responseCode)),
			slog.String("reason", reason),
		)

		pint.RespondWithPayload(w, http.StatusUnprocessableEntity, signedResponse)
		return
	}

	// Step 4. Check for duplicate envelope transfer (200 ok with signed response)
	// The last entry chain checksum is the unique identifier for a specific transfer attempt.
	// (when the same eBL is transferred multiple times, each transfer will have a different last chain entry checksum
	// because the timestamp contained in the entry will change)
	lastChainChecksum := verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum

	exists, verificationErr := s.queries.ExistsEnvelopeByLastChainEntryChecksum(ctx, lastChainChecksum)
	if verificationErr != nil && !errors.Is(verificationErr, pgx.ErrNoRows) {
		pint.RespondWithError(w, r, pint.WrapInternalError(verificationErr, "failed to check for duplicate envelope"))
		return
	}
	if exists {
		// Retrieve the previously accepted envelope to get the last transfer chain entry
		existingEnvelope, err := s.queries.GetEnvelopeByLastChainEntryChecksum(ctx, lastChainChecksum)
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to retrieve duplicate envelope"))
			return
		}

		// Get missing and received additional document checksums for the duplicate response
		// This helps the sender understand the current state of the transfer
		missingChecksums, err := s.queries.GetMissingAdditionalDocumentChecksums(ctx, existingEnvelope.ID)
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to retrieve missing documents"))
			return
		}

		receivedChecksums, err := s.queries.GetReceivedAdditionalDocumentChecksums(ctx, existingEnvelope.ID)
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to retrieve received documents"))
			return
		}

		// Create and sign the DUPE response
		signedResponse, err := s.createSignedFinishedResponse(pint.EnvelopeTransferFinishedResponse{
			LastEnvelopeTransferChainEntrySignedContentChecksum: lastChainChecksum,
			ResponseCode: pint.ResponseCodeDUPE,
			DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent: &existingEnvelope.LastTransferChainEntrySignedContent,
			MissingAdditionalDocumentChecksums:                         missingChecksums,
			ReceivedAdditionalDocumentChecksums:                        receivedChecksums,
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create DUPE response"))
			return
		}

		pint.RespondWithPayload(w, http.StatusOK, signedResponse)

		reqLogger.Info("Duplicate envelope detected",
			slog.String("last_chain_checksum", lastChainChecksum),
			slog.String("existing_envelope_reference", existingEnvelope.EnvelopeReference.String()),
			slog.String("transport_document_reference", existingEnvelope.TransportDocumentReference),
			slog.Int("missing_documents", len(missingChecksums)),
			slog.Int("received_documents", len(receivedChecksums)),
		)
		return
	}

	reqLogger.Info("Envelope verified successfully",
		slog.String("transport_document_reference", verificationResult.TransportDocumentReference),
		slog.String("transport_document_checksum", verificationResult.TransportDocumentChecksum),
		slog.String("trust_level", verificationResult.TrustLevel.String()),
		slog.String("verified_domain", verificationResult.VerifiedDomain),
		slog.String("verified_organisation", verificationResult.VerifiedOrganisation))

	// Step 5. Process new transfers
	// - if there are additonal documents required the response will be 201 Created, and the response will be unsigned
	// - if there are no additional documents required the response will be 200 OK, and the response will be signed (accepted immediately)

	// list the additional documents required for the transfer
	type additionalDoc struct {
		checksum           string
		name               string
		size               int64
		mediaType          string
		isEblVisualisation bool
	}
	additionalDocs := []additionalDoc{}

	// if there is visualization in the manifest, add it to the list of missing documents
	if verificationResult.Manifest.EBLVisualisationByCarrier != nil {
		doc := verificationResult.Manifest.EBLVisualisationByCarrier
		additionalDocs = append(additionalDocs, additionalDoc{
			checksum:           doc.DocumentChecksum,
			name:               doc.Name,
			size:               doc.Size,
			mediaType:          doc.MediaType,
			isEblVisualisation: true,
		})
	}

	// add all supporting documents to the list of missing documents
	for _, doc := range verificationResult.Manifest.SupportingDocuments {
		additionalDocs = append(additionalDocs, additionalDoc{
			checksum:           doc.DocumentChecksum,
			name:               doc.Name,
			size:               doc.Size,
			mediaType:          doc.MediaType,
			isEblVisualisation: false,
		})
	}

	// Step 6. check party exists on platform TODO
	logger.ContextRequestLogger(ctx).Warn("Party check not implemented")

	// Step 7. Store envelope and transfer chain entries on db
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

	state := "PENDING"
	if len(additionalDocs) == 0 {
		state = "ACCEPTED"
	}

	txQueries := s.queries.WithTx(tx)

	storedEnvelope, err := txQueries.CreateEnvelope(ctx, database.CreateEnvelopeParams{
		TransportDocumentReference:          verificationResult.TransportDocumentReference,
		TransportDocumentChecksum:           verificationResult.TransportDocumentChecksum,
		TransportDocument:                   envelope.TransportDocument,
		EnvelopeManifestSignedContent:       string(envelope.EnvelopeManifestSignedContent),
		LastTransferChainEntrySignedContent: string(envelope.EnvelopeTransferChain[len(envelope.EnvelopeTransferChain)-1]),
		LastTransferChainEntryChecksum:      verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum,
		TrustLevel:                          int32(verificationResult.TrustLevel),
		State:                               state,
		ResponseCode:                        nil,
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to store envelope"))
		return
	}

	for i, entry := range envelope.EnvelopeTransferChain {
		_, err = txQueries.CreateTransferChainEntry(ctx, database.CreateTransferChainEntryParams{
			EnvelopeID:    storedEnvelope.ID,
			SignedContent: string(entry),
			// #nosec G115 -- transfer chains never exceed int32 max
			Sequence: int32(i),
		})
		if err != nil {
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to store transfer chain entry"))
			return
		}
	}

	// Step 8. Create placeholder records for expected additional documents
	for _, doc := range additionalDocs {
		_, err = txQueries.CreateExpectedAdditionalDocument(ctx, database.CreateExpectedAdditionalDocumentParams{
			EnvelopeID:         storedEnvelope.ID,
			DocumentChecksum:   doc.checksum,
			DocumentName:       doc.name,
			DocumentSize:       doc.size,
			MediaType:          doc.mediaType,
			IsEblVisualisation: doc.isEblVisualisation,
		})
		if err != nil {
			logger.ContextWithLogAttrs(ctx,
				slog.String("error", err.Error()),
				slog.String("document_checksum", doc.checksum),
			)
			pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to create expected additional document record"))
			return
		}
	}

	if len(additionalDocs) > 0 {
		reqLogger.Info("Created expected additional document records",
			slog.Int("count", len(additionalDocs)))
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ContextWithLogAttrs(ctx,
			slog.String("error", err.Error()),
		)

		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to commit transaction"))
		return
	}

	reqLogger.Info("Envelope stored successfully",
		slog.String("envelope_reference", storedEnvelope.EnvelopeReference.String()),
		slog.String("transport_document_reference", verificationResult.TransportDocumentReference),
		slog.Int("transfer_chain_entries", len(verificationResult.TransferChain)))

	// Step 9 - handle request with no additional documents (immediate acceptance)
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

		pint.RespondWithPayload(w, http.StatusOK, signedResponse)
		return
	}

	// Step 10. Return response
	// because this is the start of the transfer all the additional docs are 'missing'
	missingChecksums := make([]string, len(additionalDocs))
	for i, doc := range additionalDocs {
		missingChecksums[i] = doc.checksum
	}

	response := &pint.EnvelopeTransferStartedResponse{
		EnvelopeReference:                                   storedEnvelope.EnvelopeReference.String(),
		TransportDocumentChecksum:                           verificationResult.TransportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum,
		MissingAdditionalDocumentChecksums:                  missingChecksums,
	}

	pint.RespondWithPayload(w, http.StatusCreated, response)
}
