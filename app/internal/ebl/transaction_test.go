package ebl

import (
	"strings"
	"testing"
	"time"
)

// TestTransaction_Validate covers validation of transactions, including missing action code, datetime, and invalid actor fields.
func TestTransaction_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tx      Transaction
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid transaction with all required fields",
			tx: Transaction{
				ActionCode: ActionCodeIssue,
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				Recipient: &RecipientParty{
					PartyName:   "Test Recipient",
					EblPlatform: "BOLE",
					IdentifyingCodes: []IdentifyingCode{
						{CodeListProvider: "GLEIF", PartyCode: "LEI123456"},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: false,
		},
		{
			name: "valid transaction with recipient",
			tx: Transaction{
				ActionCode: ActionCodeTransfer,
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				Recipient: &RecipientParty{
					PartyName:   "Test Recipient",
					EblPlatform: "CARX",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "GLEIF",
							PartyCode:        "LEI123456",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: false,
		},
		{
			name: "missing actionCode",
			tx: Transaction{
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "actionCode is required",
		},
		{
			name: "missing actionDateTime",
			tx: Transaction{
				ActionCode: ActionCodeIssue,
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "actionDateTime is required",
		},
		{
			name: "invalid actor - missing partyName",
			tx: Transaction{
				ActionCode: ActionCodeIssue,
				Actor: ActorParty{
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "partyName is required",
		},
		{
			name: "invalid actor - missing eblPlatform",
			tx: Transaction{
				ActionCode: ActionCodeIssue,
				Actor: ActorParty{
					PartyName: "Test Actor",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "eBLPlatform is required",
		},
		{
			name: "invalid actor - missing identifyingCodes",
			tx: Transaction{
				ActionCode: ActionCodeIssue,
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "at least one identifyingCode is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tx.ValidateStructure()
			if (err != nil) != tt.wantErr {
				t.Errorf("Transaction.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				// Check if error message contains the expected substring
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Transaction.Validate() error = %v, want error containing %v", err, tt.errMsg)
				}
			}
		})
	}
}

// testCreateTransactions tests the helper functions
// use a table test to check for valid transactions and correct action code
func TestCreateTransactions(t *testing.T) {
	// create a valid actor and recipient
	actor := ActorParty{
		PartyName:   "Test Actor",
		EblPlatform: "WAVE",
		IdentifyingCodes: []IdentifyingCode{
			{
				CodeListProvider: "W3C",
				PartyCode:        "did:example:123",
			},
		},
	}
	recipient := RecipientParty{
		PartyName:   "Test Recipient",
		EblPlatform: "BOLE",
		IdentifyingCodes: []IdentifyingCode{
			{CodeListProvider: "GLEIF", PartyCode: "LEI123456"},
		},
	}

	// create a valid actionDateTime
	actionDateTime := time.Date(2024, 4, 17, 7, 11, 19, 531000000, time.UTC)

	tests := []struct {
		name       string
		tx         Transaction
		actionCode ActionCode
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "valid issue transaction",
			tx:         CreateIssueTransaction(actor, recipient, actionDateTime),
			actionCode: ActionCodeIssue,
			wantErr:    false,
		},
		{
			name:       "valid transfer transaction",
			tx:         CreateTransferTransaction(actor, recipient, actionDateTime),
			actionCode: ActionCodeTransfer,
			wantErr:    false,
		},
		{
			name:       "valid endorse transaction",
			tx:         CreateEndorseTransaction(actor, recipient, actionDateTime),
			actionCode: ActionCodeEndorse,
			wantErr:    false,
		},
		{
			name:       "valid endorse to order transaction",
			tx:         CreateEndorseToOrderTransaction(actor, recipient, actionDateTime),
			actionCode: ActionCodeEndorseToOrder,
			wantErr:    false,
		},
		{
			name:       "valid blank endorse transaction",
			tx:         CreateBlankEndorseTransaction(actor, actionDateTime),
			actionCode: ActionCodeBlankEndorse,
			wantErr:    false,
		},
		{
			name:       "valid sign transaction",
			tx:         CreateSignTransaction(actor, actionDateTime),
			actionCode: ActionCodeSign,
			wantErr:    false,
		},
		{
			name:       "valid surrender for amendment transaction",
			tx:         CreateSurrenderForAmendmentTransaction(actor, recipient, SurrenderForAmendmentReasonCodeSWI, actionDateTime),
			actionCode: ActionCodeSurrenderForAmendment,
			wantErr:    false,
		},
		{
			name:       "valid surrender for delivery transaction",
			tx:         CreateSurrenderForDeliveryTransaction(actor, recipient, actionDateTime),
			actionCode: ActionCodeSurrenderForDelivery,
			wantErr:    false,
		},
		{
			name:       "valid SACC transaction",
			tx:         CreateSACCTransaction(actor, recipient, actionDateTime),
			actionCode: ActionCodeSACC,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.tx.ActionDateTime != actionDateTime.UTC().Format(dateTimeFormat) {
				t.Errorf("Transaction.ActionDateTime = %v, want %v", tt.tx.ActionDateTime, actionDateTime.UTC().Format(dateTimeFormat))
			}

			if tt.tx.ActionCode != tt.actionCode {
				t.Errorf("Transaction.ActionCode = %v, want %v", tt.tx.ActionCode, tt.name)
			}

			if tt.tx.Actor.PartyName != actor.PartyName {
				t.Errorf("Transaction.Actor.PartyName = %v, want %v", tt.tx.Actor.PartyName, actor)
			}
			if tt.tx.Recipient != nil && tt.tx.Recipient.PartyName != recipient.PartyName {
				t.Errorf("Transaction.Recipient.PartyName = %v, want %v", tt.tx.Recipient.PartyName, recipient)
			}

			err := tt.tx.ValidateStructure()
			if (err != nil) != tt.wantErr {
				t.Errorf("Transaction.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
