//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// PartyRequest represents the request body for creating/updating a party
type PartyRequest struct {
	PartyName string `json:"partyName"`
	Active    bool   `json:"active"`
}

// PartyResponse represents the response for party operations
type PartyResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	PartyName string `json:"partyName"`
	Active    bool   `json:"active"`
}

// TestAdminPartiesCreateAndUpdate tests creating and updating a party
func TestAdminParties_CreateAndUpdate(t *testing.T) {
	testEnv := startInProcessServer(t, "EBL2")
	defer testEnv.shutdown()

	adminURL := testEnv.baseURL + "/admin"

	// Create a party
	createReq := PartyRequest{PartyName: "Original Name", Active: true}
	body, _ := json.Marshal(createReq)
	req, _ := http.NewRequest("POST", adminURL+"/parties", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create party: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 201, got %d. Response: %s", resp.StatusCode, string(body))
	}

	var createdParty PartyResponse
	if err := json.NewDecoder(resp.Body).Decode(&createdParty); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	partyID := createdParty.ID

	// Update the party
	updateReq := PartyRequest{PartyName: "Updated Name", Active: false}
	body, _ = json.Marshal(updateReq)
	req, _ = http.NewRequest("PUT", fmt.Sprintf("%s/parties/%s", adminURL, partyID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to update party: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d. Response: %s", resp.StatusCode, string(body))
	}

	var updatedParty PartyResponse
	if err := json.NewDecoder(resp.Body).Decode(&updatedParty); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if updatedParty.PartyName != "Updated Name" {
		t.Errorf("expected party name 'Updated Name', got '%s'", updatedParty.PartyName)
	}
	if updatedParty.Active {
		t.Error("expected party to be inactive")
	}
}
