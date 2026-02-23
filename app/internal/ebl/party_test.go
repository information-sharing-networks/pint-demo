package ebl

import (
	"strings"
	"testing"
)

func TestIdentifyingCode_Validate(t *testing.T) {
	tests := []struct {
		name    string
		code    IdentifyingCode
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid identifying code",
			code: IdentifyingCode{
				CodeListProvider: "W3C",
				PartyCode:        "did:example:123",
			},
			wantErr: false,
		},
		{
			name: "valid with codeListName",
			code: IdentifyingCode{
				CodeListProvider: "GLEIF",
				PartyCode:        "LEI123456",
				CodeListName:     stringPtr("LEI"),
			},
			wantErr: false,
		},
		{
			name: "missing codeListProvider",
			code: IdentifyingCode{
				PartyCode: "did:example:123",
			},
			wantErr: true,
			errMsg:  "codeListProvider is required",
		},
		{
			name: "missing partyCode",
			code: IdentifyingCode{
				CodeListProvider: "W3C",
			},
			wantErr: true,
			errMsg:  "partyCode is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.code.ValidateStructure()
			if (err != nil) != tt.wantErr {
				t.Errorf("IdentifyingCode.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("IdentifyingCode.Validate() error = %v, want %v", err, tt.errMsg)
			}
		})
	}
}

func TestActorParty_Validate(t *testing.T) {
	tests := []struct {
		name    string
		party   ActorParty
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid actor party",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid with represented party",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
				RepresentedParty: &RepresentedActorParty{
					PartyName: "Represented Party",
				},
			},
			wantErr: false,
		},
		{
			name: "missing partyName",
			party: ActorParty{
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
			},
			wantErr: true,
			errMsg:  "partyName is required",
		},
		{
			name: "missing eblPlatform",
			party: ActorParty{
				PartyName: "Test Party",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
			},
			wantErr: true,
			errMsg:  "eBLPlatform is required",
		},
		{
			name: "missing identifyingCodes",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
			},
			wantErr: true,
			errMsg:  "at least one identifyingCode is required",
		},
		{
			name: "invalid identifyingCode",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						// Missing PartyCode
					},
				},
			},
			wantErr: true,
			errMsg:  "partyCode is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.party.ValidateStructure()
			if (err != nil) != tt.wantErr {
				t.Errorf("ActorParty.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ActorParty.Validate() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
