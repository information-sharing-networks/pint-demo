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
//	@Description	Use this endpoint to initiate an eBL envelope transfer on the server.
//	@Description
//	@Description	The sending platform must supply a request containing the transport document (eBL),
//	@Description	a signed envelope manifest, and the complete transfer chain.
//	@Description
//	@Description	The receiving platform will check that the signatures are verified, checksums validated,
//	@Description	and the transfer chain integrity.
//	@Description
//	@Description	The response includes an `envelopeReference` that must be used in subsequent API calls
//	@Description	to upload additional documents and finish the transfer.
//
//	@Tags			PINT
//
//	@Param			request	body		ebl.EblEnvelope							true	"eBL envelope containing transport document, signed manifest, and transfer chain"
//
//	@Success		201		{object}	pint.EnvelopeTransferStartedResponse	"Transfer started, additional documents required"
//	@Success		200		{object}	pint.EnvelopeTransferStartedResponse	"Transfer accepted or duplicate detected"
//	@Failure		400		{object}	pint.ErrorResponse						"Malformed request"
//	@Failure		409		{object}	pint.ErrorResponse						"Disputed envelope"
//	@Failure		422		{object}	pint.ErrorResponse						"Signature or validation failed"
//
//	@Router			/v3/envelopes [post]
func (s *StartTransferHandler) HandleStartTransfer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqLogger := logger.ContextRequestLogger(ctx)

	var envelope ebl.EblEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		reqLogger.Warn("Failed to decode envelope", slog.String("error", err.Error()))
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
		reqLogger.Warn("Envelope verification failed", slog.String("error", err.Error()))
		pint.RespondWithError(w, r, err)
		return
	}

	// Check for duplicate by last chain checksum
	lastChainChecksum := verificationResult.LastEnvelopeTransferChainEntrySignedContentChecksum

	exists, err := s.queries.ExistsEnvelopeByLastChainEntryChecksum(ctx, lastChainChecksum)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		reqLogger.Error("Database error checking for duplicate", slog.String("error", err.Error()))
		pint.RespondWithError(w, r, pint.NewInternalError("database error"))
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

	reqLogger.Info("Envelope verified successfully",
		slog.String("transport_document_reference", verificationResult.TransportDocumentReference),
		slog.String("transport_document_checksum", verificationResult.TransportDocumentChecksum),
		slog.String("trust_level", verificationResult.TrustLevel.String()),
		slog.String("verified_domain", verificationResult.VerifiedDomain),
		slog.String("verified_organisation", verificationResult.VerifiedOrganisation))

	// Determine sender platform from last chain entry
	senderPlatform := verificationResult.LastTransferChainEntry.EblPlatform

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
		TrustLevel:                          verificationResult.TrustLevel.String(),
		State:                               "pending",
		ResponseCode:                        nil,
	})
	if err != nil {
		reqLogger.Error("Failed to create envelope", slog.String("error", err.Error()))
		pint.RespondWithError(w, r, pint.NewInternalError("failed to store envelope"))
		return
	}

	// Store transfer chain entries
	for i := range verificationResult.TransferChain {
		_, err := s.queries.CreateTransferChainEntry(ctx, database.CreateTransferChainEntryParams{
			EnvelopeID:    storedEnvelope.ID,
			SignedContent: string(envelope.EnvelopeTransferChain[i]),
			Sequence:      int64(i),
		})
		if err != nil {
			reqLogger.Error("Failed to create transfer chain entry",
				slog.Int("sequence", i),
				slog.String("error", err.Error()))
			pint.RespondWithError(w, r, pint.NewInternalError("failed to store transfer chain"))
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
