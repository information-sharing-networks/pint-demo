package pint

// State machine for managing the state of an eBL as it is processed by the platform

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
)

// this state machine determines if an action code can be accepted by a platform for a given eBL
// the rules are:
// if platform A accepts a transfer from B then further requests from B for the same eBL are denied
// if platform A accepts a SURR action no further request are allowed on the eBL
// if platform A accepts an endorsement from platform B then the next action must be a transfer from B to A
// if platform A accepts any action from platform B, all requests from other platforms for the same BL are denied

// CurrentTransportDocumentState is the current state of the eBL as stored in the database
type CurrentTransportDocumentState struct {
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

// CanAccept determines if the next state is valid given the current state
// A reason is returned in either case for logging/error reporting
// if an error is returned it indicates a bug in the code as an unexpected combination of current and next state was received
func (current *CurrentTransportDocumentState) CanAccept(next requestedAction, thisPlatformCode string) (accept bool, reason string, error error) {

	if !current.Accepted {
		return false, fmt.Sprintf("previous action (%s) not yet accepted for this eBL", current.ActionCode), nil
	}

	switch current.ActionCode {
	case ebl.ActionCodeSurrenderForDelivery, ebl.ActionCodeSurrenderForAmendment:

		return false, "surrender already pending for this eBL", nil

	case ebl.ActionCodeSACC:
		return false, "eBL already surrendered, no further action permitted", nil

	case ebl.ActionCodeSign, ebl.ActionCodeIssue:

		// sign and issue do not block subsequent actions
		return true, fmt.Sprintf("action %s accepted for this eBL (current state: %s)", next.ActionCode, current.ActionCode), nil

	case ebl.ActionCodeTransfer:

		if !current.Accepted {
			return false, "transfer already pending for this eBL", nil
		}

		if next.PlatformCode == thisPlatformCode {
			return false, "internal error", fmt.Errorf("%s can't transfer to itself", thisPlatformCode)
		}

		if current.ReceivedByPlatformCode != thisPlatformCode {
			return false, "internal error", fmt.Errorf("internal error: the current platform %s is not the recipient of the last accepted transfer (%s)", thisPlatformCode, current.ReceivedByPlatformCode)
		}
		return true, fmt.Sprintf("transfer accepted from %s to %s", current.ReceivedByPlatformCode, next.PlatformCode), nil

	case ebl.ActionCodeSREJ:

		if current.ActionCode != ebl.ActionCodeSurrenderForAmendment &&
			current.ActionCode != ebl.ActionCodeSurrenderForDelivery {
			return false, fmt.Sprintf("SREJ can only be accepted after SURRENDER_FOR_AMENDMENT or SURRENDER_FOR_DELIVERY, (have %s)", current.ActionCode), nil
		}

		return true, "acknowldegement of rejected surrender request for this eBL accepted", nil
	}
	return false, "internal error", fmt.Errorf("unhandled action code, %s", current.ActionCode)
}

// todo state CanAccept CanDeliver
