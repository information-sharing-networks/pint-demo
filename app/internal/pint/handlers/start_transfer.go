package handlers

// start_transfer.go implements the POST /v3/envelopes endpoint for starting envelope transfers.

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

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
}

// NewStartTransferHandler creates a new handler for starting envelope transfers
func NewStartTransferHandler(
	queries *database.Queries,
	keyManager *pint.KeyManager,
	signingKey any,
	x5cCertChain []*x509.Certificate,
	x5cCustomRoots *x509.CertPool,
) *StartTransferHandler {
	return &StartTransferHandler{
		queries:        queries,
		keyManager:     keyManager,
		signingKey:     signingKey,
		x5cCertChain:   x5cCertChain,
		x5cCustomRoots: x5cCustomRoots,
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
//	@Description	`201 Created` - Transfer started (not yet accepted)
//	@Description	- The envelope transfer is now active
//	@Description	- Additional documents listed in the EnvelopeManifest are required
//	@Description	- Sender must transfer documents, then call "Finish envelope transfer" endpoint
//	@Description	- Only at finish will the transfer be accepted or rejected (signed response)
//	@Description
//	@Description	Retry handling - if the sender attempts to start a transfer for an eBL that already has an active transfer,
//	@Description	the receiver assumes the sender has lost track of the state of the transer.
//	@Description	In this case, the request is treated as a retry and the existing envelope
//	@Description	reference and current missing documents are returned with HTTP 201.
//	@Description
//	@Description	`200 OK` - Transfer accepted immediately (with signed response)
//	@Description	- No additional documents required, OR receiver already has all documents
//	@Description	- the signed response includes `responseCode`: `RECE` (accepted) or `DUPE` (duplicate)
//	@Description
//	@Description	`DUPE` means this transfer was previously accepted - in this case the response
//	@Description	also includes the last accepted transfer chain entry
//	@Description	`duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent` which the sender can use
//	@Description	to verify which transfer was accepted.
//
//	@Tags			PINT
//
//	@Param			request	body		ebl.EblEnvelope								true	"eBL envelope containing transport document, signed manifest, and transfer chain"
//
//	@Success		200		{object}	pint.SignedEnvelopeTransferFinishedResponse	"Transfer accepted immediately (RECE or DUPE)"
//	@Success		201		{object}	pint.EnvelopeTransferStartedResponse		"Transfer started (active), additional documents required"
//	@Failure		400		{object}	pint.ErrorResponse							"Malformed request"
//	@Failure		409		{object}	pint.ErrorResponse							"Disputed envelope (DISE)"
//	@Failure		422		{object}	pint.ErrorResponse							"Signature or validation failed (BSIG/BENV)"
//
//	@Router			/v3/envelopes [post]
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
		pint.RespondWithError(w, r, ebl.WrapEnvelopeError(err, "envelope verification failed"))
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
