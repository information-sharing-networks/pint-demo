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
)

// StartTransferHandler handles POST /v3/envelopes requests
type StartTransferHandler struct {
	queries *database.Queries

	// keyManager contains the public keys used to verify JWS signatures received from other platforms
	keyManager *pint.KeyManager

	// ed25519.PrivateKey or *rsa.PrivateKey used for signing responses to the sender
	signingKey any

	// X.509 certificate chain for signing (optional)
	x5cCertChain []*x509.Certificate

	// Custom root CAs for x5c verification (optional, nil = system roots)
	x5cCustomRoots *x509.CertPool

	// Minimum trust level required for signatures (server config)
	minTrustLevel int32
}

// NewStartTransferHandler creates a new handler for starting envelope transfers
func NewStartTransferHandler(
	queries *database.Queries,
	keyManager *pint.KeyManager,
	signingKey any,
	x5cCertChain []*x509.Certificate,
	x5cCustomRoots *x509.CertPool,
	minTrustLevel int32,
) *StartTransferHandler {
	return &StartTransferHandler{
		queries:        queries,
		keyManager:     keyManager,
		signingKey:     signingKey,
		x5cCertChain:   x5cCertChain,
		x5cCustomRoots: x5cCustomRoots,
		minTrustLevel:  minTrustLevel,
	}
}

// createSignedRejectionResponse creates a signed rejection response for envelope transfer failures.
// This is used when the envelope verification fails or trust level is insufficient.
// Returns a SignedEnvelopeTransferFinishedResponse with the appropriate response code and reason.
func (s *StartTransferHandler) createSignedRejectionResponse(lastChainChecksum string, responseCode pint.ResponseCode, reason string) (*pint.SignedEnvelopeTransferFinishedResponse, error) {
	// Create the response payload
	response := pint.EnvelopeTransferFinishedResponse{
		LastEnvelopeTransferChainEntrySignedContentChecksum: lastChainChecksum,
		ResponseCode: responseCode,
		Reason:       &reason,
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return nil, pint.WrapInternalError(err, "failed to marshal rejection response")
	}

	// Sign
	jws, err := crypto.SignJSON(jsonBytes, s.signingKey, s.x5cCertChain)
	if err != nil {
		return nil, pint.WrapInternalError(err, "failed to sign rejection response")
	}

	return &pint.SignedEnvelopeTransferFinishedResponse{
		SignedContent: jws,
	}, nil
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
//	@Description	In the normal flow, you receive a signed response containing
//	@Description	a JWS token with the error details in the payload.
//	@Description
//	@Description	`422 Unprocessable Entity` indicates the platform has rejected the transfer.
//	@Description	The response body contains a JWS token with `responseCode` of `BSIG` (signature failure)
//	@Description	or `BENV` (envelope validation failure).
//	@Description
//	@Description	**Trust Level Failures**
//	@Description	This platform enforces a minimum trust level for signatures,
//	@Description	based on the x5c header in the envelope manifsest JWS.
//	@Description	- Trust level 1 means that the JWS must contain a valid Extended Validation (EV)
//	@Description	or Organization Validation (OV) certificate.
//	@Description	- Trust level 2 means the JWS must contain a valid certificate,
//	@Description	but Domain Validation (DV) certificate are allowed.
//	@Description	- Trust level 3 is the lowest trust level, and means that a JWS
//	@Description	will be accepted even if no x5c header is present.
//	@Description
//	@Description	The trust level is checked after signature verification, and a valid JWS with an insufficient trust
//	@Description	level will also return a `422 Unprocessable Entity` response.
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
// @Tags			PINT
//
// @Param			request	body		ebl.EblEnvelope								true	"eBL envelope containing transport document, signed manifest, and transfer chain"
//
// @Success		200		{object}	pint.SignedEnvelopeTransferFinishedResponse	"Signed response - Transfer accepted immediately (RECE or DUPE) - see the 'default' response for details of the response payload"
// @Success		201		{object}	pint.EnvelopeTransferStartedResponse			"Transfer started but not yet accepted"
// @Failure		400		{object}	pint.ErrorResponse							"Malformed request"
// @Failure		422		{object}	pint.SignedEnvelopeTransferFinishedResponse	"Signed response - Signature or validation failed (BSIG/BENV) - see the 'default' response for details of the response payload"
// @Failure		500		{object}	pint.ErrorResponse							"Internal error processing request"
// @Success		default	{object}	pint.EnvelopeTransferFinishedResponse		"documentation only (not returned directly) - decoded payload of the signed response"
//
// @Router			/v3/envelopes [post]
func (s *StartTransferHandler) HandleStartTransfer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqLogger := logger.ContextRequestLogger(ctx)

	var envelope ebl.EblEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		pint.RespondWithError(w, r, ebl.WrapEnvelopeError(err, "failed to decode envelope JSON"))
		return
	}
	defer r.Body.Close()

	// Verify envelope signatures, checksums, and chain integrity
	verificationResult, err := ebl.VerifyEnvelopeTransfer(ebl.EnvelopeVerificationInput{
		Envelope:    &envelope,
		RootCAs:     s.x5cCustomRoots,
		KeyProvider: s.keyManager,
	})
	if err != nil {
		// Verification failed - return signed rejection response with BSIG or BENV
		// Extract the last chain checksum from the envelope for the signed response
		var lastChainChecksum string
		if len(envelope.EnvelopeTransferChain) > 0 {
			lastEntryJWS := envelope.EnvelopeTransferChain[len(envelope.EnvelopeTransferChain)-1]
			lastChainChecksum, _ = crypto.Hash([]byte(lastEntryJWS))
		}

		// Determine response code based on error type
		responseCode := pint.ResponseCodeBENV // Default to envelope validation error
		var cryptoErr *crypto.CryptoError
		if errors.As(err, &cryptoErr) {
			if cryptoErr.Code() == crypto.ErrCodeInvalidSignature || cryptoErr.Code() == crypto.ErrCodeCertificate {
				responseCode = pint.ResponseCodeBSIG
			}
		}

		response, signErr := s.createSignedRejectionResponse(
			lastChainChecksum,
			responseCode,
			err.Error(),
		)
		if signErr != nil {
			// If we can't sign the response, fall back to unsigned error
			pint.RespondWithError(w, r, ebl.WrapEnvelopeError(err, "envelope verification failed"))
			return
		}

		reqLogger.Warn("Envelope verification failed",
			slog.String("response_code", string(responseCode)),
			slog.String("error", err.Error()),
		)
		pint.RespondWithJSON(w, http.StatusUnprocessableEntity, response)
		return
	}

	// check the trust level meets the platform minimum
	if verificationResult.TrustLevel > crypto.TrustLevel(s.minTrustLevel) {
		// Trust level insufficient - reject with BSIG
		response, err := s.createSignedRejectionResponse(
			verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum,
			pint.ResponseCodeBSIG,
			fmt.Sprintf("Trust level %s does not meet minimum required level",
				verificationResult.TrustLevel.String()),
		)
		if err != nil {
			pint.RespondWithError(w, r, err)
			return
		}
		pint.RespondWithJSON(w, http.StatusUnprocessableEntity, response)
		return
	}

	// Check for duplicate by last chain checksum
	lastChainChecksum := verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum

	// The receiving platform either
	//  - Accepts the envelope transfer (if there are no additional documents to be transferred,
	//  or if it concludes that it is already in the possession of all the additional documents mentioned in the EnvelopeManifest),
	//  - Or indicates that it is a duplicate (it already accepted the envelope tranfer with the same contents)
	exists, err := s.queries.ExistsEnvelopeByLastChainEntryChecksum(ctx, lastChainChecksum)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to check for duplicate envelope"))
		return
	}
	if exists {
		// TODO: complete DUPE handling
		reqLogger.Info("Duplicate envelope detected",
			slog.String("last_chain_checksum", lastChainChecksum))

		pint.RespondWithError(w, r, pint.NewInternalError("duplicate handling not implemented"))
		return

	}

	// TODO: enforce trust levels

	// TODO: transaction handling

	reqLogger.Info("Envelope verified successfully",
		slog.String("transport_document_reference", verificationResult.TransportDocumentReference),
		slog.String("transport_document_checksum", verificationResult.TransportDocumentChecksum),
		slog.String("trust_level", verificationResult.TrustLevel.String()),
		slog.String("verified_domain", verificationResult.VerifiedDomain),
		slog.String("verified_organisation", verificationResult.VerifiedOrganisation))

	// Determine sender platform from last chain entry
	senderPlatform := verificationResult.LastTransferChainEntry.EblPlatform

	// TODO state depends on the presence of additional documents

	// Store envelope in database
	storedEnvelope, err := s.queries.CreateEnvelope(ctx, database.CreateEnvelopeParams{
		TransportDocumentReference:          verificationResult.TransportDocumentReference,
		TransportDocumentChecksum:           verificationResult.TransportDocumentChecksum,
		TransportDocument:                   envelope.TransportDocument,
		EnvelopeManifestSignedContent:       string(envelope.EnvelopeManifestSignedContent),
		LastTransferChainEntrySignedContent: string(envelope.EnvelopeTransferChain[len(envelope.EnvelopeTransferChain)-1]),
		LastTransferChainEntryChecksum:      verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum,
		SenderPlatform:                      senderPlatform,
		SenderEblPlatform:                   &verificationResult.VerifiedDomain,
		TrustLevel:                          int32(verificationResult.TrustLevel),
		State:                               "PENDING",
		ResponseCode:                        nil,
	})
	if err != nil {
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to store envelope"))
		return
	}

	for i, entry := range envelope.EnvelopeTransferChain {
		_, err = s.queries.CreateTransferChainEntry(ctx, database.CreateTransferChainEntryParams{
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
	reqLogger.Info("Envelope stored successfully",
		slog.String("envelope_reference", storedEnvelope.EnvelopeReference.String()),
		slog.String("transport_document_reference", verificationResult.TransportDocumentReference),
		slog.Int("transfer_chain_entries", len(verificationResult.TransferChain)))

	// Determine missing additional documents
	missingDocs := []string{}
	if verificationResult.Manifest.EBLVisualisationByCarrier != nil {
		missingDocs = append(missingDocs, verificationResult.Manifest.EBLVisualisationByCarrier.DocumentChecksum)
	}
	for _, doc := range verificationResult.Manifest.SupportingDocuments {
		missingDocs = append(missingDocs, doc.DocumentChecksum)
	}

	response := &pint.EnvelopeTransferStartedResponse{
		EnvelopeReference:                                   storedEnvelope.EnvelopeReference.String(),
		TransportDocumentChecksum:                           verificationResult.TransportDocumentChecksum,
		LastEnvelopeTransferChainEntrySignedContentChecksum: verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum,
		MissingAdditionalDocumentChecksums:                  missingDocs,
	}

	statusCode := http.StatusCreated
	if len(missingDocs) == 0 {
		statusCode = http.StatusOK
	}

	pint.RespondWithJSON(w, statusCode, response)
}
