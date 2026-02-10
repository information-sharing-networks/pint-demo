//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

func TestReceiverValidation(t *testing.T) {
	testEnv := startInProcessServer(t, "EBL1")
	defer testEnv.shutdown()

	receiverValidationURL := testEnv.baseURL + "/v3/receiver-validation"

	partyServiceURL := testEnv.cfg.PartyServiceBaseURL

	// set up testdata
	activeParty := createParty(t, partyServiceURL, PartyRequest{PartyName: "Test Ltd", Active: true})
	createPartyCode(t, partyServiceURL, activeParty.ID, PartyIdentifyingCodeRequest{
		CodeListProvider: "GLEIF",
		PartyCode:        "123",
		CodeListName:     stringPtr("LEI"),
	})
	activePartyNoCodeListName := createParty(t, partyServiceURL, PartyRequest{PartyName: "Test Ltd - No codeListName", Active: true})
	createPartyCode(t, partyServiceURL, activePartyNoCodeListName.ID, PartyIdentifyingCodeRequest{
		CodeListProvider: "EBL1",
		PartyCode:        "456",
	})

	inactiveParty := createParty(t, partyServiceURL, PartyRequest{PartyName: "Inactive Ltd", Active: false})
	createPartyCode(t, partyServiceURL, inactiveParty.ID, PartyIdentifyingCodeRequest{
		CodeListProvider: "GLEIF",
		PartyCode:        "789",
		CodeListName:     stringPtr("LEI"),
	})
	tests := []struct {
		name              string
		validationRequest pint.ReceiverValidationRequest
		expectedStatus    int
		expectedPartyName string
		expectErrorCode   pint.ErrorCode
	}{
		{
			name: "valid_party_with_LEI",
			validationRequest: pint.ReceiverValidationRequest{
				CodeListProvider: "GLEIF",
				PartyCode:        "123",
				CodeListName:     stringPtr("LEI"),
			},
			expectedStatus:    http.StatusOK,
			expectedPartyName: "Test Ltd",
		},
		{
			name: "valid_party_without_codeListName",
			validationRequest: pint.ReceiverValidationRequest{
				CodeListProvider: "EBL1",
				PartyCode:        "456",
			},
			expectedStatus:    http.StatusOK,
			expectedPartyName: "Test Ltd - No codeListName",
		},
		{
			name: "party_not_found",
			validationRequest: pint.ReceiverValidationRequest{
				CodeListProvider: "GLEIF",
				PartyCode:        "N/A",
			},
			expectedStatus:  http.StatusNotFound,
			expectErrorCode: pint.ErrCodeUnknownParty,
		},
		{
			name: "inactive_party",
			validationRequest: pint.ReceiverValidationRequest{
				CodeListProvider: "GLEIF",
				PartyCode:        "789",
			},
			expectedStatus:  http.StatusNotFound,
			expectErrorCode: pint.ErrCodeUnknownParty,
		},
		{
			name: "missing_code_list_provider",
			validationRequest: pint.ReceiverValidationRequest{
				PartyCode: "SOMECODE",
			},
			expectedStatus:  http.StatusBadRequest,
			expectErrorCode: pint.ErrCodeMalformedRequest,
		},
		{
			name: "missing_party_code",
			validationRequest: pint.ReceiverValidationRequest{
				CodeListProvider: "GLEIF",
			},
			expectedStatus:  http.StatusBadRequest,
			expectErrorCode: pint.ErrCodeMalformedRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute: Call receiver validation
			body, _ := json.Marshal(tt.validationRequest)
			req, _ := http.NewRequest("POST", receiverValidationURL, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to call receiver-validation: %v", err)
			}
			defer resp.Body.Close()

			// Assert: Check status code
			if resp.StatusCode != tt.expectedStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d, got %d. Response: %s", tt.expectedStatus, resp.StatusCode, string(body))
			}

			// Assert: Check response body
			if tt.expectedStatus == http.StatusOK {
				var validationResp pint.ReceiverValidationResponse
				if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
					t.Fatalf("failed to decode validation response: %v", err)
				}
				if validationResp.PartyName != tt.expectedPartyName {
					t.Errorf("expected party name '%s', got '%s'", tt.expectedPartyName, validationResp.PartyName)
				}
			} else if tt.expectErrorCode > 0 {
				var errorResp pint.ErrorResponse
				if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if errorResp.Errors[0].ErrorCode != tt.expectErrorCode {
					t.Errorf("expected error status code %d, got %d", tt.expectErrorCode, errorResp.Errors[0].ErrorCode)
				}
			}
		})
	}
}

// Helper functions for test setup

func createParty(t *testing.T, partyServiceURL string, party PartyRequest) PartyResponse {
	t.Helper()
	body, _ := json.Marshal(party)
	req, _ := http.NewRequest("POST", partyServiceURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create party: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("failed to create test party - expected status 201, got %d. Response: %s", resp.StatusCode, string(body))
	}

	var createdParty PartyResponse
	if err := json.NewDecoder(resp.Body).Decode(&createdParty); err != nil {
		t.Fatalf("test data creation err: failed to decode party response: %v", err)
	}

	return createdParty
}

func createPartyCode(t *testing.T, partyServiceURL, partyID string, code PartyIdentifyingCodeRequest) {
	t.Helper()
	body, _ := json.Marshal(code)

	url := fmt.Sprintf("%s/%s/codes", partyServiceURL, partyID)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create party code: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 201, got %d. Response: %s", resp.StatusCode, string(body))
	}
}

// PartyIdentifyingCodeRequest represents the request body for creating a party identifying code
type PartyIdentifyingCodeRequest struct {
	CodeListProvider string  `json:"code_list_provider"`
	PartyCode        string  `json:"party_code"`
	CodeListName     *string `json:"code_list_name,omitempty"`
}

func stringPtr(s string) *string {
	return &s
}
