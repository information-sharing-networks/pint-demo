//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
	"github.com/information-sharing-networks/pint-demo/app/internal/services"
)

// test the receiver validation endpoint
func TestReceiverValidation(t *testing.T) {
	testEnv := startInProcessServer(t, "EBL1")
	defer testEnv.shutdown()

	receiverValidationURL := testEnv.baseURL + "/v3/receiver-validation"

	// create test party data
	_ = createTestParty(t, testEnv.queries, "Test Ltd", true, []testIdentifyingCode{
		{codeListProvider: "GLEIF", partyCode: "123", codeListName: stringPtr("LEI")},
	})
	_ = createTestParty(t, testEnv.queries, "Test Ltd - No codeListName", true, []testIdentifyingCode{
		{codeListProvider: "EBL1", partyCode: "456"},
	})
	_ = createTestParty(t, testEnv.queries, "Inactive Ltd", false, []testIdentifyingCode{
		{codeListProvider: "GLEIF", partyCode: "789", codeListName: stringPtr("LEI")},
	})

	tests := []struct {
		name              string
		validationRequest services.PartyIdentifyingCode
		expectedStatus    int
		expectedPartyName string
		expectErrorCode   pint.ErrorCode
	}{
		{
			name: "valid_party_with_LEI",
			validationRequest: services.PartyIdentifyingCode{
				CodeListProvider: "GLEIF",
				PartyCode:        "123",
				CodeListName:     stringPtr("LEI"),
			},
			expectedStatus:    http.StatusOK,
			expectedPartyName: "Test Ltd",
		},
		{
			name: "valid_party_without_codeListName",
			validationRequest: services.PartyIdentifyingCode{
				CodeListProvider: "EBL1",
				PartyCode:        "456",
			},
			expectedStatus:    http.StatusOK,
			expectedPartyName: "Test Ltd - No codeListName",
		},
		{
			name: "party_not_found",
			validationRequest: services.PartyIdentifyingCode{
				CodeListProvider: "GLEIF",
				PartyCode:        "N/A",
			},
			expectedStatus:  http.StatusNotFound,
			expectErrorCode: pint.ErrCodeUnknownParty,
		},
		{
			name: "inactive_party",
			validationRequest: services.PartyIdentifyingCode{
				CodeListProvider: "GLEIF",
				PartyCode:        "789",
			},
			expectedStatus:  http.StatusNotFound,
			expectErrorCode: pint.ErrCodeUnknownParty,
		},
		{
			name: "missing_code_list_provider",
			validationRequest: services.PartyIdentifyingCode{
				PartyCode: "SOMECODE",
			},
			expectedStatus:  http.StatusBadRequest,
			expectErrorCode: pint.ErrCodeMalformedRequest,
		},
		{
			name: "missing_party_code",
			validationRequest: services.PartyIdentifyingCode{
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

func stringPtr(s string) *string {
	return &s
}
