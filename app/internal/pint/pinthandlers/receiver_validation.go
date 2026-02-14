package handlers

// receiver_validation.go implements the POST /v3/receiver-validation endpoint

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
	"github.com/information-sharing-networks/pint-demo/app/internal/services"
)

// ReceiverValidationHandler handles POST /v3/receiver-validation requests
type ReceiverValidationHandler struct {
	partyValidator services.PartyValidator
}

// NewReceiverValidationHandler creates a new handler for receiver validation
func NewReceiverValidationHandler(partyValidator services.PartyValidator) *ReceiverValidationHandler {
	return &ReceiverValidationHandler{
		partyValidator: partyValidator,
	}
}

// HandleReceiverValidation godoc
//
//	@Summary		Validate a receiver party
//	@Description	Request the name of a party (legal entity) given a party code. This enables the sending service to
//	@Description	to check the receiver party exists and is active before sending an eBL (similar to how bank
//	@Description	transfers enable users to confirm the receiver's account name before confirming the transfer).
//	@Description
//	@Description	A successful response asserts that the platform will accept an eBL for the account or user
//	@Description	denoted by the provided identifying code.
//	@Description
//	@Description	Note the sender can provider more than one identity code for the same party (e.g. both a DID and a LEI for the same company).
//	@Description	The receiver platform will reject transfers where these codes resolve to different parties on their system.
//	@Description.
//	@Tags		PINT
//	@Accept		json
//	@Produce	json
//	@Param		request	body		services.PartyIdentifyingCode	true	"Party identifying code"
//	@Success	200		{object}	pint.ReceiverValidationResponse	"Party found and active"
//	@Failure	400		{object}	pint.ErrorResponse				"Invalid request"
//	@Failure	404		{object}	pint.ErrorResponse				"Party not found or inactive"
//	@Failure	500		{object}	pint.ErrorResponse				"Internal error"
//	@Router		/v3/receiver-validation [post]
func (h *ReceiverValidationHandler) HandleReceiverValidation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req services.PartyIdentifyingCode
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pint.RespondWithError(w, r, pint.WrapMalformedRequestError(err, "failed to decode request JSON"))
		return
	}
	defer r.Body.Close()

	//  Validate required fields
	if req.CodeListProvider == "" {
		pint.RespondWithError(w, r, pint.NewMalformedRequestError("codeListProvider is required"))
		return
	}
	if req.PartyCode == "" {
		pint.RespondWithError(w, r, pint.NewMalformedRequestError("partyCode is required"))
		return
	}

	// Validate the party using the party validator service
	partyName, err := h.partyValidator.ValidatePartyIdentifyingCode(ctx, req)
	if err != nil {
		if errors.Is(err, services.ErrPartyNotFound) {
			// Return 404 for unknown/inactive parties
			pint.RespondWithError(w, r, pint.NewUnknownPartyError("party not found or inactive"))
			return
		}

		// Internal error
		pint.RespondWithError(w, r, pint.WrapInternalError(err, "failed to validate party"))
		return
	}

	// Return successful response
	response := pint.ReceiverValidationResponse{
		PartyName: partyName,
	}

	pint.RespondWithPayload(w, http.StatusOK, response)
}
