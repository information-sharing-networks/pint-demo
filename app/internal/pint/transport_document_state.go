package pint

// State machine for managing the state of an eBL as it is processes new envelopes for the eBL
// see also ebl/action_codes.go for the state machine for the transfer chain (checks internal logic of the transfer chain)

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
)

// lastReceivedAction is the current state of the eBL as stored in the database
type lastReceivedAction struct {
	EnvelopeID                uuid.UUID
	TransportDocumentChecksum string
	ActionCode                ebl.ActionCode
	SentByPlatformCode        string
	ReceivedByPlatformCode    string
	CreatedAt                 time.Time
	AcceptedAt                *time.Time
	Accepted                  bool
}

// requestedAction is the state of the eBL that is being requested
type requestedAction struct {
	// ActionCode is the action code of the next proposed action
	ActionCode ebl.ActionCode

	// PlatformCode is the next intended recipient platform
	PlatformCode string
}

// CanAccept determines if the platform can accept the requested action for an eBL
//
// return values:
// A reason is returned in either case for logging/error reporting
// if an error is returned it indicates a bug in the code as an unexpected combination of current and next state was received
func (lastReceivedAction *lastReceivedAction) CanAccept(requestedAction requestedAction, currentPlatformCode string) (accept bool, reason string, error error) {

	// todo - call ebl state transition to make sure we are not creating an invalid chain
	// some checks are repeated below as 'belt and braces' and for clarity
	// this function just needs to do the platform specific checks

	// handle in progress actions
	// TODO: Where a transfer is pending because the sending platform sent one or more impossible additional document checksums,
	// the sender can never complete the transfer and the BL is stuck permanently at "started but not accepted".
	// Do we need a VOID state to cancel these actions?
	if !lastReceivedAction.Accepted {
		return false, fmt.Sprintf("previous action (%s) for this eBL is in progress but not yet accepted for this eBL", lastReceivedAction.ActionCode), nil
	}

	// transfers block further actions from the same platform - can't be detected by transfer chain validation as it does not know which platform is processing the request
	// TODO this can be caught in the state machine for action ...
	if lastReceivedAction.ActionCode == ebl.ActionCodeTransfer &&
		lastReceivedAction.ReceivedByPlatformCode == requestedAction.PlatformCode {
		return false, fmt.Sprintf("transfer was already acccepted from %s", lastReceivedAction.ReceivedByPlatformCode), nil
	}

	// check if the next action is compatible with the current state of the eBL
	switch requestedAction.ActionCode {
	case ebl.ActionCodeIssue:
		// internal error - issuance is a one time action so should not appear in the state machine
		return false, "internal error", fmt.Errorf("issuance is a one time action so should not appear in the state machine")

	case ebl.ActionCodeSign:
		// platforms can sign at anytime and can pass to another platform for non-repudiation purposes(TODO - is this right?)
		return true, fmt.Sprintf("action %s accepted for this eBL (current state: %s)", requestedAction.ActionCode, lastReceivedAction.ActionCode), nil

	case ebl.ActionCodeTransfer:
		// internal error - the current platform must be the recipient of the last accepted transfer
		if lastReceivedAction.ReceivedByPlatformCode != currentPlatformCode {
			return false, "internal error", fmt.Errorf("internal error: the current platform %s is not the recipient of the last accepted transfer (%s)", currentPlatformCode, lastReceivedAction.ReceivedByPlatformCode)
		}

		switch {
		// transfer must be addressed to the current platform
		case requestedAction.PlatformCode != currentPlatformCode:
			return false, "internal error", fmt.Errorf("%s cannot proccess a transfer addressed to: %s", currentPlatformCode, requestedAction.PlatformCode)

		// the current platform must be the recipient of the last accepted transfer
		case lastReceivedAction.ReceivedByPlatformCode != currentPlatformCode:
			return false, "internal error", fmt.Errorf("internal error: the current platform %s is not the recipient of the last accepted transfer (%s)", currentPlatformCode, lastReceivedAction.ReceivedByPlatformCode)

		// transfers must be previously endorsed to the recipient platform
		case lastReceivedAction.ActionCode != ebl.ActionCodeEndorse && lastReceivedAction.ActionCode != ebl.ActionCodeEndorseToOrder && lastReceivedAction.ActionCode != ebl.ActionCodeBlankEndorse:
			return false, "internal error", fmt.Errorf("transfer can only be accepted after an endorsement, (have %s)", lastReceivedAction.ActionCode)
		}

		return true, fmt.Sprintf("transfer accepted from %s to %s", lastReceivedAction.ReceivedByPlatformCode, requestedAction.PlatformCode), nil

	case ebl.ActionCodeSREJ:
		// SREJ can only be accepted after a surrender request
		if lastReceivedAction.ActionCode != ebl.ActionCodeSurrenderForAmendment &&
			lastReceivedAction.ActionCode != ebl.ActionCodeSurrenderForDelivery {
			return false, fmt.Sprintf("SREJ can only be accepted after SURRENDER_FOR_AMENDMENT or SURRENDER_FOR_DELIVERY, (have %s)", lastReceivedAction.ActionCode), nil
		}

		return true, "accepted recipt of rejected surrender for this eBL", nil

	case ebl.ActionCodeEndorse, ebl.ActionCodeEndorseToOrder, ebl.ActionCodeBlankEndorse:
		return true, fmt.Sprintf("endorsement accepted for this eBL (current state: %s)", lastReceivedAction.ActionCode), nil
	}
	return false, "internal error", fmt.Errorf("bug: unhandled eBL transition, %s", lastReceivedAction.ActionCode)
}

// TODO: CanDeliver()
// TODO: HasPossession()
// TODO: IsSurenderRequested()
// TODO: IsSurrenderAccepted()
// TODO: IsSurrenderRejected()
