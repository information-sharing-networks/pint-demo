package ebl

// transport_document.go provides functions for working with DCSA transport documents (e.g. Bill of Lading)

import (
	"encoding/json"
	"fmt"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// TransportDocumentJSON is a helper type for working with transport document JSON.
type TransportDocument json.RawMessage

// Canonicalize returns the canonicalized transport document JSON.
func (t TransportDocument) Canonicalize() ([]byte, error) {
	c, err := crypto.CanonicalizeJSON([]byte(t))
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize transport document: %w", err)
	}
	return c, nil
}

// Checksum returns the SHA-256 checksum of the canonicalized transport document JSON.
func (t TransportDocument) Checksum() (TransportDocumentChecksum, error) {
	c, err := t.Canonicalize()
	if err != nil {
		return "", err
	}
	h, err := crypto.Hash(c)
	if err != nil {
		return "", fmt.Errorf("failed to hash transport document: %w", err)
	}
	return TransportDocumentChecksum(h), nil
}

// Type returns the type of eBL document (Straight, To-Order, Blank Endorsed)
func (t TransportDocument) Type() (TransportDocumentType, error) {
	var td struct {
		IsToOrder       *bool `json:"isToOrder"`
		DocumentParties struct {
			Endorsee *EndorseeParty `json:"endorsee"`
		} `json:"documentParties"`
	}

	if err := json.Unmarshal([]byte(t), &td); err != nil {
		return "", fmt.Errorf("failed to parse transport document: %w", err)
	}

	if td.IsToOrder == nil {
		return "", fmt.Errorf("failed to determine transport document type: isToOrder not present")
	}

	if !*td.IsToOrder && td.DocumentParties.Endorsee != nil {
		return "", fmt.Errorf("isToOrder is false but endorsee is present")
	}

	if !*td.IsToOrder {
		return TransportDocumentTypeStraightBL, nil
	}

	if td.DocumentParties.Endorsee == nil {
		return TransportDocumentTypeToOrderBL, nil
	}

	return TransportDocumentTypeBlankEndorsedBL, nil
}

// TransportDocumentChecksum is the SHA-256 checksum of the canonicalized transport document JSON.
type TransportDocumentChecksum string

// TransportDocumentType is used to classify the type of eBL document.
type TransportDocumentType string

const (
	// TransportDocumentTypeStraightBL - identified by `EblEnvelope.TransportDocument.isToOrder` = false
	//
	// Straight BLs are consigned directly to a name party and cannot be transferred to another platform.
	TransportDocumentTypeStraightBL TransportDocumentType = "Straight Bill of Lading"

	// TransportDocumentTypeBlankEndorsedBL is identified by `EblEnvelope.TransportDocument.isToOrder = true,
	// and the absence of an `endorsee` document party in `EblEnvelope.transportDocument.documentParties`
	//
	// The eBL can be freely endorsed and transferred until the final possessor redeems it by executing a `SURRENDER_FOR_DELIVERY` transaction.
	TransportDocumentTypeBlankEndorsedBL TransportDocumentType = "Blank Endorsed Bill of Lading"

	// TransportDocumentTypeToOrderBL is used for To-Order/ Negotiable eBL documents.
	// They are identified by `EblEnvelope.TransportDocument.isToOrder` = true,
	// and the presence of an `endorsee` document party in `EblEnvelope.transportDocument.documentParties`.
	//
	// If the current endorsee is also in possession of the eBL, that party may endorse the EBL to  another party
	// - either on the same eBL Platform or on a different eBL Platform - thereby making that other party the new endorsee.
	//  This is done by executing a transaction with `transaction.actionCode` set to `ENDORSE`, `ENDORSE_TO_ORDER` or `BLANK_ENDORSE`.
	TransportDocumentTypeToOrderBL TransportDocumentType = "To-Order Bill of Lading"
)

// EndorseeParty represents the party to whom the eBL is endorsed.
type EndorseeParty struct {
	PartyName        string            `json:"partyName"`
	IdentifyingCodes []IdentifyingCode `json:"identifyingCodes"`
}
