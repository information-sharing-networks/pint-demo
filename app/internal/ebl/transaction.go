package ebl

// transaction.go provides functions for creating transactions to be included in transfer chain entries.
// you can use the helpers below to create the transactions you need, they will be correctly populated with the
// mandatory fields.
//
// The helpers use UTC time for the actionDateTime and default to time.Now() unless a non-nil time.Time is passed.
//
import (
	"fmt"
	"time"
)

const dateTimeFormat = "2006-01-02T15:04:05.000Z"

// Transaction represents a action performed on a platform for a specific eBL
type Transaction struct {

	// actionCode: The transaction type (ISSUE, TRANSFER, ENDORSE, SURRENDER_FOR_DELIVERY, etc.)
	ActionCode ActionCode `json:"actionCode"`

	// actor: The legal entity (party) performing the action (required)
	Actor ActorParty `json:"actor"`

	// recipient: The party receiving the action (nil for SIGN and BLANK_ENDORSE)
	Recipient *RecipientParty `json:"recipient,omitempty"`

	// actionDateTime: RFC3339 timestamp (UTC) when the transaction was created
	ActionDateTime string `json:"actionDateTime"` // RFC3339 format with millisecond precision

	// reasonCode: Reason code for SURRENDER_FOR_AMENDMENT (optional)
	// Possible values: SWTP (Switch to paper), COD (Change of destination), SWI (Switch BL)
	ReasonCode *SurrenderForAmendmentReasonCode `json:"reasonCode,omitempty"`

	// comments: Free text comment (optional)
	Comments *string `json:"comments,omitempty"`

	// auditReference: Audit identifier from eBL Solution Provider (optional)
	AuditReference *string `json:"auditReference,omitempty"`
}

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (t *Transaction) ValidateStructure() error {
	if t.ActionCode == "" {
		return NewEnvelopeError("actionCode is required")
	}
	if err := t.Actor.ValidateStructure(); err != nil {
		return WrapEnvelopeError(err, "actor")
	}
	if t.ActionDateTime == "" {
		return NewEnvelopeError("actionDateTime is required")
	}

	// SIGN and BLANK_ENDORSE must not have a recipient; all other action codes require one
	switch t.ActionCode {
	case ActionCodeSign, ActionCodeBlankEndorse:
		if t.Recipient != nil {
			return NewEnvelopeError(fmt.Sprintf("%s must not have a recipient", t.ActionCode))
		}
	default:
		if t.Recipient == nil {
			return NewEnvelopeError(fmt.Sprintf("%s requires a recipient", t.ActionCode))
		}
		if err := t.Recipient.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, "recipient")
		}
	}

	// reasonCode is only applicable for SURRENDER_FOR_AMENDMENT
	if t.ReasonCode != nil && t.ActionCode != ActionCodeSurrenderForAmendment {
		return NewEnvelopeError(fmt.Sprintf("reasonCode is only applicable for %s, not %s", ActionCodeSurrenderForAmendment, t.ActionCode))
	}

	return nil
}

// CreateIssueTransaction creates an ISSUE transaction.
//
// This is used in when the carrier issues the eBL to the recipient (shipper).
//
// Returns a Transaction ready to include in the first transfer chain entry.
func CreateIssueTransaction(actor ActorParty, recipient RecipientParty, actionTime time.Time) Transaction {
	// If the caller passes time.Time{}, use Now()
	if actionTime.IsZero() {
		actionTime = time.Now()

	}
	return Transaction{
		ActionCode:     ActionCodeIssue,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: actionTime.UTC().Format(dateTimeFormat),
	}
}

// CreateTransferTransaction creates a TRANSFER transaction.
//
// This is used when the actor transfers the eBL to another party. The recipient may be
// on another platform.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateTransferTransaction(actor ActorParty, recipient RecipientParty, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeTransfer,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
	}
}

// CreateEndorseTransaction creates an ENDORSE transaction.
//
// This is used when the actor endorses the eBL to a named party.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateEndorseTransaction(actor ActorParty, recipient RecipientParty, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeEndorse,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
	}
}

// CreateEndorseToOrderTransaction creates an ENDORSE_TO_ORDER transaction.
//
// This is used when the actor endorses the document to order of the recipient, allowing the recipient to further endorse the eBL to another party)
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateEndorseToOrderTransaction(actor ActorParty, recipient RecipientParty, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeEndorseToOrder,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
	}
}

// CreateBlankEndorseTransaction creates a BLANK_ENDORSE transaction.
//
// This is used when the actor endorses the document without specifying a named endorsee.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateBlankEndorseTransaction(actor ActorParty, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeBlankEndorse,
		Actor:          actor,
		Recipient:      nil,
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
	}
}

// CreateSignTransaction creates a SIGN transaction.
//
// This is used when a party signs the eBL while in their possession (no recipient).
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSignTransaction(actor ActorParty, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeSign,
		Actor:          actor,
		Recipient:      nil, // SIGN transactions don't have a recipient
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
	}
}

// CreateSurrenderForAmendmentTransaction creates a SURRENDER_FOR_AMENDMENT transaction.
//
// This is used when the actor surrenders the eBL for amendment.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSurrenderForAmendmentTransaction(actor ActorParty, recipient RecipientParty, reasonCode SurrenderForAmendmentReasonCode, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeSurrenderForAmendment,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
		ReasonCode:     &reasonCode,
	}
}

// CreateSurrenderForDeliveryTransaction creates a SURRENDER_FOR_DELIVERY transaction.
//
// This is used when the actor surrenders the eBL for delivery.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSurrenderForDeliveryTransaction(actor ActorParty, recipient RecipientParty, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeSurrenderForDelivery,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
	}
}

// CreateSACCTransaction creates a SACC transaction.
//
// This is used when the carrier accepts a surrender request.
//
// Returns a Transaction ready to include in a transfer chain entry.
func CreateSACCTransaction(actor ActorParty, recipient RecipientParty, actionDateTime time.Time) Transaction {
	if actionDateTime.IsZero() {
		actionDateTime = time.Now()
	}
	return Transaction{
		ActionCode:     ActionCodeSACC,
		Actor:          actor,
		Recipient:      &recipient,
		ActionDateTime: actionDateTime.UTC().Format(dateTimeFormat),
	}
}
