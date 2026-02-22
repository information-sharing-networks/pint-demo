package ebl

// transfer_chain.go provides the builders for transfer chain entries.
//

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// EnvelopeTransferChainEntry represents a batch of transactions that happened on a single platform.
// This is the payload that gets signed as an EnvelopeTransferChainEntrySignedContent item in
// the transfer chain list in the envelope.
type EnvelopeTransferChainEntry struct {

	// EblPlatform: The eBL platform code (e.g., "WAVE", "BOLE", "CARX") responsible for this entry
	EblPlatform string `json:"eblPlatform"`

	// TransportDocumentChecksum - this should not change for the lifetime of the eBL.
	TransportDocumentChecksum TransportDocumentChecksum `json:"transportDocumentChecksum"`

	// PreviousEnvelopeTransferChainEntrySignedContentChecksum is the checksum of the previous entry in the transfer chain,
	// and should only be included if this is not the first entry in the transfer chain.
	PreviousEnvelopeTransferChainEntrySignedContentChecksum *TransferChainEntrySignedContentChecksum `json:"previousEnvelopeTransferChainEntrySignedContentChecksum,omitempty"`

	// IssuanceManifestSignedContent: JWS of IssuanceManifest (required for first entry only)
	// The issuance manifest is created and signed the carrier when the eBL is issued and proves the integrity of the transport document and the issueTo party data.
	// It should not change for the lifetime of the eBL.
	IssuanceManifestSignedContent *IssuanceManifestSignedContent `json:"issuanceManifestSignedContent,omitempty"`

	// ControlTrackingRegistry: URI of CTR (optional, only in first entry). Example: https://ctr.dcsa.org/v1
	ControlTrackingRegistry *string `json:"controlTrackingRegistry,omitempty"`

	// Transactions: List of transactions (at least one required)
	Transactions []Transaction `json:"transactions"`
}

// SHA-256 of transfer chain entry JWS token.
// The token is the JWS string created whe signing an EnvelopeTransferChainEntry payload.
type TransferChainEntrySignedContentChecksum string

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification
func (b *EnvelopeTransferChainEntry) ValidateStructure(isFirstEntry bool) error {
	if b.EblPlatform == "" {
		return NewEnvelopeError("eBLPlatform is required")
	}
	if b.TransportDocumentChecksum == "" {
		return NewEnvelopeError("transportDocumentChecksum is required")
	}
	if len(b.Transactions) == 0 {
		return NewEnvelopeError("at least one transaction is required")
	}

	// Validate first vs subsequent entry rules
	hasIssuanceManifest := b.IssuanceManifestSignedContent != nil
	hasPreviousEntry := b.PreviousEnvelopeTransferChainEntrySignedContentChecksum != nil

	if isFirstEntry && !hasIssuanceManifest {
		return NewEnvelopeError("issuanceManifestSignedContent is required for first entry")
	}

	if !isFirstEntry && !hasPreviousEntry {
		return NewEnvelopeError("previousEnvelopeTransferChainEntrySignedContentChecksum is required in all entries apart from the first entry")
	}

	if hasIssuanceManifest && hasPreviousEntry {
		return NewEnvelopeError("entry cannot have both issuanceManifestSignedContent and previousEnvelopeTransferChainEntrySignedContentChecksum")
	}

	if !isFirstEntry && b.ControlTrackingRegistry != nil {
		return NewEnvelopeError("controlTrackingRegistry should only be present in first entry")
	}

	// TODO - is there a register of valid CTRs - or is this something that is configured at service start up?
	if b.ControlTrackingRegistry != nil {
		// Validate CTR URL format
		if _, err := url.Parse(*b.ControlTrackingRegistry); err != nil {
			return WrapEnvelopeError(err, "invalid controlTrackingRegistry URL")
		}
	}

	// Subsequent entry specific validation
	if hasPreviousEntry {
		if b.ControlTrackingRegistry != nil {
			return NewEnvelopeError("controlTrackingRegistry should only be present in first entry")
		}
	}

	// Validate each transaction
	for i, tx := range b.Transactions {
		if err := tx.ValidateStructure(); err != nil {
			return WrapEnvelopeError(err, fmt.Sprintf("transaction[%d]", i))
		}
	}

	return nil
}

// Sign creates the EnvelopeTransferChainEntrySignedContent JWS string.
//
// The privateKey can be either ed25519.PrivateKey or *rsa.PrivateKey.
// If certChain is provided, the x5c header will be included in the JWS for non-repudiation.
//
// Returns a JWS compact serialization string ready to include in Envelope.envelopeTransferChain
func (b *EnvelopeTransferChainEntry) Sign(privateKey any, certChain []*x509.Certificate) (EnvelopeTransferChainEntrySignedContent, error) {
	// Marshal to JSON
	jsonBytes, err := json.Marshal(b)
	if err != nil {
		return "", WrapInternalError(err, "failed to marshal transfer chain entry")
	}

	// Canonicalize the payload
	canonicalPayload, err := crypto.CanonicalizeJSON(jsonBytes)
	if err != nil {
		return "", WrapInternalError(err, "failed to canonicalize transfer chain entry")
	}

	// Sign
	jws, err := crypto.SignJSON(canonicalPayload, privateKey, certChain)
	if err != nil {
		return "", WrapSignatureError(err, "failed to sign transfer chain entry")
	}

	return EnvelopeTransferChainEntrySignedContent(jws), nil
}

// EnvelopeTransferChainEntryBuilder helps build transfer chain entries and handles checksum calculations, validations and so on.
//
// The transfer chain represents the complete history of an eBL document, including issuance,
// transfers, endorsements, and surrenders across different eBL platforms.
// Each entry in the transfer chain represents a batch of transactions that happened on a single platform.
type EnvelopeTransferChainEntryBuilder struct {

	// isFirstEntry: true if this is the first entry in the transfer chain.
	// this is needed because the contents of the initial entry are different to subsequent entries
	isFirstEntry bool

	// transportDocumentChecksum: SHA-256 checksum of the canonical transport document
	transportDocumentChecksum TransportDocumentChecksum

	// eblPlatform: ebl platform code responsible for this entry
	eblPlatform string

	// issuanceManifestSignedContent: JWS of IssuanceManifest (required for first entry only)
	issuanceManifestSignedContent *IssuanceManifestSignedContent

	// controlTrackingRegistry: URI of CTR (optional, only in first entry). Example: https://ctr.dcsa.org/v1
	controlTrackingRegistry *string

	// previousEnvelopeTransferChainEntrySignedContent: checksum of the JWS of previous entry in the transfer chain (required for subsequent entries only)
	previousEnvelopeTransferChainEntrySignedContentChecksum *TransferChainEntrySignedContentChecksum

	// transactions: List of transactions for this entry
	transactions []Transaction
}

// NewFirstEnvelopeTransferChainEntryBuilder creates a builder to create a new transfer chain entry.
//
// To create a new entry:
//  1. Create transactions using transaction.go helpers (CreateTransferTransaction, CreateEndorseTransaction, etc.)
//  2. Create an EnvelopeTransferChainEntryBuilder
//  3. Add the required fields using the builder methods
//  4. Call Build() to create the EnvelopeTransferChainEntry struct
//  5. Sign the entry using Sign()
//  6. Add the signed entry to the envelope transfer chain
func NewEnvelopeTransferChainEntryBuilder(isFirstEntry bool) *EnvelopeTransferChainEntryBuilder {
	return &EnvelopeTransferChainEntryBuilder{
		isFirstEntry: isFirstEntry,
	}
}

// WithTransportDocumentChecksum sets the pre-computed transport document checksum.
func (b *EnvelopeTransferChainEntryBuilder) WithTransportDocumentChecksum(checksum TransportDocumentChecksum) *EnvelopeTransferChainEntryBuilder {
	b.transportDocumentChecksum = checksum
	return b
}

// WithEBLPlatform sets the eBL platform code (e.g., "WAVE", "BOLE", "CARX")
func (b *EnvelopeTransferChainEntryBuilder) WithEBLPlatform(platform string) *EnvelopeTransferChainEntryBuilder {
	b.eblPlatform = platform
	return b
}

// WithTransaction adds a transaction to this entry
// You can call this multiple times to add multiple transactions to a single entry
func (b *EnvelopeTransferChainEntryBuilder) WithTransaction(transaction Transaction) *EnvelopeTransferChainEntryBuilder {
	b.transactions = append(b.transactions, transaction)
	return b
}

// WithTransactions sets all transactions for this entry at once
func (b *EnvelopeTransferChainEntryBuilder) WithTransactions(transactions []Transaction) *EnvelopeTransferChainEntryBuilder {
	b.transactions = transactions
	return b
}

// WithControlTrackingRegistry sets the CTR URI (optional, only for first entry)
// Example: "https://ctr.dcsa.org/v1"
func (b *EnvelopeTransferChainEntryBuilder) WithControlTrackingRegistry(uri string) *EnvelopeTransferChainEntryBuilder {
	b.controlTrackingRegistry = &uri
	return b
}

// WithIssuanceManifestSignedContent sets the issuance manifest JWS. Required only for first entry -
// do not use for subsequent entries.
func (b *EnvelopeTransferChainEntryBuilder) WithIssuanceManifestSignedContent(jws IssuanceManifestSignedContent) *EnvelopeTransferChainEntryBuilder {
	b.issuanceManifestSignedContent = &jws
	return b
}

// WithPreviousEnvelopeTransferChainEntrySignedContentChecksum sets the checksum of the previous entry JWS token.
// This is used to link this entry to the previous one in the chain and should not be used for the first entry in the chain.
// It is required for all subsequent entries.
func (b *EnvelopeTransferChainEntryBuilder) WithPreviousEnvelopeTransferChainEntrySignedContentChecksum(checksum TransferChainEntrySignedContentChecksum) *EnvelopeTransferChainEntryBuilder {
	b.previousEnvelopeTransferChainEntrySignedContentChecksum = &checksum
	return b
}

// Build creates the EnvelopeTransferChainEntry with the required checksums calculated.
//
// the build process is as follows:
//   - If this is a subsequent entry, calculate the checksum of the previous entry JWS
//   - Assemble the EnvelopeTransferChainEntry struct
//   - Validate the entry
//
// Note it is necessary to include the transport document checksum in every entry in the transfer chain
// to prevent replay attacks (where an attacker replaces the last entry in the chain with a previous entry from a different chain).
// The transport document checksum is validated when the eBL platform first receives the issuance request and is unchanged for the lifetime of the eBL.
//
// returns *EnvelopeTransferChainEntry: Ready to sign

func (b *EnvelopeTransferChainEntryBuilder) Build() (*EnvelopeTransferChainEntry, error) {

	// Build the entry using the pre-computed checksum
	entry := &EnvelopeTransferChainEntry{
		EblPlatform:                   b.eblPlatform,
		TransportDocumentChecksum:     b.transportDocumentChecksum,
		Transactions:                  b.transactions,
		IssuanceManifestSignedContent: b.issuanceManifestSignedContent,
		ControlTrackingRegistry:       b.controlTrackingRegistry,
		PreviousEnvelopeTransferChainEntrySignedContentChecksum: b.previousEnvelopeTransferChainEntrySignedContentChecksum,
	}

	if err := entry.ValidateStructure(b.isFirstEntry); err != nil {
		return nil, WrapEnvelopeError(err, "entry validation failed")
	}

	return entry, nil
}
