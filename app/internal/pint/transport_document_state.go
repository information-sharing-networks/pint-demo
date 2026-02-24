package pint

// State machine for managing the state of an eBL as it is processed by the platform

import (
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
//
// PlatformEBLState is reconstructed by replaying accepted events from transport_document_events
// for a given transport_document_checksum, ordered by created_at.
type PlatformEBLState struct {
	CurrentPossessor string // from_platform_code of the last accepted possession-transfer event

	// Set after ENDORSE/ENDORSE_TO_ORDER - the to_platform_code of that event.
	// Next accepted event must be TRANSFER from that platform.
	PendingEndorseeTo *string

	// True when an unaccepted SURRENDER_FOR_DELIVERY or SURRENDER_FOR_AMENDMENT exists.
	// Derived from: exists a row with action_code IN ('SURRENDER_FOR_DELIVERY', 'SURRENDER_FOR_AMENDMENT')
	// AND accepted = false for this checksum.
	AwaitingSurrender bool

	// True when SACC has been accepted.
	Finalized bool
}

// CurrentTransportDocumentState is the current state of the eBL as stored in the database
type CurrentTransportDocumentState struct {
	EnvelopeID                uuid.UUID
	TransportDocumentChecksum string
	ActionCode                ebl.ActionCode
	SendingPlatformCode       string
	ReceivingPlatformCode     string
	CreatedAt                 time.Time
	AcceptedAt                *time.Time
	Accepted                  bool
}

// requestedAction is the state of the eBL that is being requested
type requestedAction struct {
	// ActionCode is the action code of the next proposed action
	ActionCode ebl.ActionCode
	// the intended recipient platform
	ReceivingPlatformCode string
}

// CanAccept determines if the next state is valid given the current state
// A reason is returned in either case for logging/error reporting
// if an error is returned it is an internal error
func (current *CurrentTransportDocumentState) CanAccept(next requestedAction, requestedByPlatformCode string) (accept bool, reason string, err error) {

	switch current.ActionCode {
	case ebl.ActionCodeSurrenderForDelivery, ebl.ActionCodeSurrenderForAmendment:

		if current.Accepted {
			return false, "surrender already accepted for this eBL", nil
		}
		return false, "surrender already pending for this eBL", nil

	case ebl.ActionCodeSACC:
		return false, "eBL already surrendered, no further action permitted", nil

	case ebl.ActionCodeTransfer:

		if !current.Accepted {
			return false, "transfer already pending for this eBL", nil
		}

		if next.ReceivingPlatformCode == requestedByPlatformCode {
			return false, "%s can't transfer to itself", nil
		}

		// if current.ToPlatformCode != next.ToPlatformCode {

		// if current.ReceivedByPlatformCode != next.ReceivedByPlatformCode {
		// if current.SentByPlatformCode != next.SentByPlatformCode {
		if current.ReceivingPlatformCode != next.ReceivingPlatformCode {
			return false, "transfer already pending for this eBL", nil
		}

	}
	return false, "internal error: unhandled action code", nil
}

// todo state CanAccept CanDeliver
