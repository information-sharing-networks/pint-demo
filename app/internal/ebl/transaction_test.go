package ebl

import (
	"strings"
	"testing"
)

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
