package ebl

import "slices"

// EnvelopeState is used to ensure that transfer chain actionCodes are sequenced correctly.
type EnvelopeState string

const (
	EnvelopeStateUnset                 EnvelopeState = ""
	EnvelopeStateIssue                 EnvelopeState = "ISSUE"
	EnvelopeStateTransfer              EnvelopeState = "TRANSFER"
	EnvelopeStateEndorse               EnvelopeState = "ENDORSE"
	EnvelopeStateEndorseToOrder        EnvelopeState = "ENDORSE_TO_ORDER"
	EnvelopeStateBlankEndorse          EnvelopeState = "BLANK_ENDORSE"
	EnvelopeStateSign                  EnvelopeState = "SIGN"
	EnvelopeStateSurrenderForAmendment EnvelopeState = "SURRENDER_FOR_AMENDMENT"
	EnvelopeStateSurrenderForDelivery  EnvelopeState = "SURRENDER_FOR_DELIVERY"
	EnvelopeStateSACC                  EnvelopeState = "SACC" // used by the carrier to accept a surrender request.
	EnvelopeStateSREJ                  EnvelopeState = "SREJ" // used by the carrier to reject a surrender request.
)

// TODO: do the transition rules need to vary depending on the type of BL (to order, blank endorse, etc)?
var validEnvelopeStateTransitions = map[EnvelopeState][]EnvelopeState{
	EnvelopeStateIssue:                 {EnvelopeStateTransfer, EnvelopeStateEndorse},
	EnvelopeStateTransfer:              {EnvelopeStateTransfer, EnvelopeStateEndorse, EnvelopeStateEndorseToOrder, EnvelopeStateBlankEndorse, EnvelopeStateSign, EnvelopeStateSurrenderForAmendment, EnvelopeStateSurrenderForDelivery},
	EnvelopeStateEndorse:               {EnvelopeStateTransfer, EnvelopeStateEndorse, EnvelopeStateEndorseToOrder, EnvelopeStateBlankEndorse, EnvelopeStateSign, EnvelopeStateSurrenderForAmendment, EnvelopeStateSurrenderForDelivery},
	EnvelopeStateSurrenderForAmendment: {EnvelopeStateSACC, EnvelopeStateSREJ},
	EnvelopeStateSurrenderForDelivery:  {EnvelopeStateSACC, EnvelopeStateSREJ},
	EnvelopeStateSACC:                  {}, // terminal state
	EnvelopeStateSREJ:                  {}, // terminal state
}

// isValidEnvelopeStateTransition checks if a transition from currentState to nextState is valid
// according to the DCSA specification.
//
// Returns true if the transition is allowed, false otherwise.
func isValidEnvelopeStateTransition(currentState, nextState EnvelopeState) bool {
	validTransitions, ok := validEnvelopeStateTransitions[currentState]
	if !ok {
		return false
	}
	return slices.Contains(validTransitions, nextState)
}

// SurrenderReasonCode represents the reason for SURRENDER_FOR_AMENDMENT according to DCSA specification.
type SurrenderReasonCode string

const (
	// SurrenderReasonCodeSWTP indicates a switch to paper bill of lading
	SurrenderReasonCodeSWTP SurrenderReasonCode = "SWTP"

	// SurrenderReasonCodeCOD indicates a change of destination
	SurrenderReasonCodeCOD SurrenderReasonCode = "COD"

	// SurrenderReasonCodeSWI indicates a switch of bill of lading
	SurrenderReasonCodeSWI SurrenderReasonCode = "SWI"
)
