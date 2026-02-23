package ebl

// action_codes.go defines the DCSA action codes and the valid transitions between them.

import "slices"

// ActionCode is the action code of a transaction in the transfer chain.
type ActionCode string

const (
	// ActionCodeUnset is the zero value for ActionCode.
	ActionCodeUnset ActionCode = ""

	// ActionCodeIssue is used when the carrier issues the eBL to the recipient (shipper).
	ActionCodeIssue ActionCode = "ISSUE"

	// ActionCodeTransfer is used when the possessor transfers the eBL to another party.
	ActionCodeTransfer ActionCode = "TRANSFER"

	// ActionCodeEndorse is used when the possessor endorses a negotiable eBL to another party (endorsee)
	// The recipient CANNOT further endorse the eBL.
	// The endorsement must always take place on the eBL platform of the current endorsee, who also holds possession of the eBL.
	//
	// If the new endorsee is on a different eBL platform than the current endorsee,
	// the envelope transfer process is used to notify them of the `ENDORSE` transaction for non-repudiation purposes.
	// However, this transaction does NOT result in the transfer of possession of the eBL contained in the envelope.
	ActionCodeEndorse ActionCode = "ENDORSE"

	// ActionCodeEndorseToOrder is used to endorse a negotiable eBL to a new endorsee.
	// The recipient CAN further endorse the eBL to another party.
	// The endorsement must always take place on the eBL platform of the current endorsee, who also holds possession of the eBL.
	//
	// If the new endorsee is on a different eBL platform than the current endorsee, the envelope transfer process is used to notify them of the `ENDORSE_TO_ORDER`
	// transaction for non-repudiation purposes. However, this transaction does NOT result in the transfer of possession of the eBL contained in the envelope.
	ActionCodeEndorseToOrder ActionCode = "ENDORSE_TO_ORDER"

	// ActionCodeBlankEndorse is used when the possessor endorses the eBL in blank, meaning that the endorsement does not specify a recipient.
	//
	// The endorsement must always take place on the eBL platform of the current possessor of the eBL.
	ActionCodeBlankEndorse ActionCode = "BLANK_ENDORSE"

	// ActionCodeSign is used by an actor to visibly confirm their possession of the eBL within the chain.
	// This action has no designated recipient and can only be performed while the actor is the current possessor of the eBL.
	ActionCodeSign ActionCode = "SIGN"

	// ActionCodeSurrenderForDelivery is used when party requests delivery of the goods
	//
	// If the request is not addressed to the carrier that issued the eBL or to their legal representative,
	// then the receiving platform should reject the envelope transfer (BENV).
	ActionCodeSurrenderForDelivery ActionCode = "SURRENDER_FOR_DELIVERY"

	// ActionCodeSurrenderForAmendment is used when the possessor surrenders the eBL so that the carrier can issue an amended version.
	//
	// If the request is not addressed to the carrier that issued the eBL or to their legal representative,
	// then the receiving platform should reject the envelope transfer (BENV).
	//
	// If the request is accepted (see the `SACC` action code for details), the amendments to the eBL are agreed upon outside the PINT API
	// (for example, through the DCSA EBL API). Once accepted, the original eBL and its envelope transfer chain are voided,
	// and the amended eBL must be reissued with a new envelope transfer chain (see the `ISSUE` action code description above).
	//
	// This action code is also used when switching the eBL to a physical document (“switch to paper”),
	// which is treated as part of the amendment process in the DCSA standard.
	ActionCodeSurrenderForAmendment ActionCode = "SURRENDER_FOR_AMENDMENT"

	// ActionCodeSACC is used by the carrier to accept a surrender request.
	// (initiated with either the `SURRENDER_FOR_DELIVERY` or `SURRENDER_FOR_AMENDMENT` action code).
	//
	// If the surrendering party is on a different platform than the carrier,
	// the envelope transfer process is used to notify them of the `SACC` transaction for non-repudiation purposes.
	// However, this transaction does NOT result in the transfer of possession of the eBL contained in the envelope.
	//
	// Once a `SACC` transaction has been recorded, no further transactions are permitted.
	// Any changes to the envelope transfer chain involving new transactions after a `SACC` transaction
	// are invalid and must be rejected (BENV)
	ActionCodeSACC ActionCode = "SACC"

	// used by the carrier to reject a surrender request.
	// (initiated with either the `SURRENDER_FOR_DELIVERY` or `SURRENDER_FOR_AMENDMENT` action code),
	// and return possession of the eBL to the party that submitted the surrender request.
	ActionCodeSREJ ActionCode = "SREJ"
)

// TODO: confirm the rules for the action code state transition
var validActionCodeTransitions = map[ActionCode][]ActionCode{
	ActionCodeIssue:                 {ActionCodeTransfer, ActionCodeSign},
	ActionCodeTransfer:              {ActionCodeTransfer, ActionCodeEndorse, ActionCodeEndorseToOrder, ActionCodeBlankEndorse, ActionCodeSign, ActionCodeSurrenderForAmendment, ActionCodeSurrenderForDelivery},
	ActionCodeEndorse:               {ActionCodeTransfer},
	ActionCodeEndorseToOrder:        {ActionCodeTransfer},
	ActionCodeBlankEndorse:          {ActionCodeTransfer, ActionCodeSign, ActionCodeSurrenderForAmendment, ActionCodeSurrenderForDelivery},
	ActionCodeSign:                  {ActionCodeTransfer, ActionCodeEndorse, ActionCodeEndorseToOrder, ActionCodeBlankEndorse, ActionCodeSign, ActionCodeSurrenderForAmendment, ActionCodeSurrenderForDelivery},
	ActionCodeSurrenderForAmendment: {ActionCodeSACC, ActionCodeSREJ},
	ActionCodeSurrenderForDelivery:  {ActionCodeSACC, ActionCodeSREJ},
	ActionCodeSREJ:                  {ActionCodeTransfer, ActionCodeEndorse, ActionCodeEndorseToOrder, ActionCodeBlankEndorse, ActionCodeSign, ActionCodeSurrenderForAmendment, ActionCodeSurrenderForDelivery},
	ActionCodeSACC:                  {}, // terminal state
}

// isValidActionCodeTransition checks if a transition from currentState to nextState is valid
// according to the DCSA specification.
//
// Returns true if the transition is allowed, false otherwise.
func isValidActionCodeTransition(currentState, nextState ActionCode) bool {
	validTransitions, ok := validActionCodeTransitions[currentState]
	if !ok {
		return false
	}
	return slices.Contains(validTransitions, nextState)
}

// SurrenderForAmendmentReasonCode represents the reason for SURRENDER_FOR_AMENDMENT according to DCSA specification.
type SurrenderForAmendmentReasonCode string

const (
	// SurrenderForAmendmentReasonCodeSWTP indicates a switch to paper bill of lading
	SurrenderForAmendmentReasonCodeSWTP SurrenderForAmendmentReasonCode = "SWTP"

	// SurrenderForAmendmentReasonCodeCOD indicates a change of destination
	SurrenderForAmendmentReasonCodeCOD SurrenderForAmendmentReasonCode = "COD"

	// SurrenderForAmendmentReasonCodeSWI indicates a switch of bill of lading
	SurrenderForAmendmentReasonCodeSWI SurrenderForAmendmentReasonCode = "SWI"
)
