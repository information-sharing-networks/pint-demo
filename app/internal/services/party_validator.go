// services provides external service integrations for the PINT server (CTR, party validation etc.)
//
// This package contains service clients that can use local HTTP handlers or remote APIs.
// The clients are used by handlers that can be configured for external services, e.g the receiver validation handler.
//
// To add support for a new party service:
//  1. Create a new type that implements the PartyValidator interface
//  2. Add a case for it in NewPartyValidator() based on the service name
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/information-sharing-networks/pint-demo/app/internal/config"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
)

// PartyIdentifyingCode is the request body for POST /v3/receiver-validation
type PartyIdentifyingCode struct {
	// CodeListProvider is the provider of the code list (e.g., "WAVE", "CARX", "GLEIF", "W3C")
	CodeListProvider string `json:"codeListProvider" example:"W3C"`

	// PartyCode is the code to identify the party as provided by the code list provider
	PartyCode string `json:"partyCode" example:"did:web:example.com:party:12345"`

	// CodeListName is optional - the name of the code list (e.g., "DID", "LEI", "DUNS")
	CodeListName *string `json:"codeListName,omitempty" example:"DID"`
}

// PartyValidator validates party identifying codes and returns party information.
type PartyValidator interface {
	// ValidatePartyIdentifyingCode validates a party identifying code and returns the party name if found and active.
	// This method is used by the /v3/receiver-validation endpoint handler.
	// Returns ErrPartyNotFound if the party is not found, inactive, or the code list provider is not supported.
	ValidatePartyIdentifyingCode(ctx context.Context, identifyingCode PartyIdentifyingCode) (partyName string, err error)

	// GetPartyIDByIdentifyingCode returns the internal party ID for a given identifying code.
	// This method is used by the receiving platform to validate that multiple identifing codes map to the same party.
	// Returns ErrPartyNotFound if the party is not found, inactive, or the code list provider is not supported.
	GetPartyIDByIdentifyingCode(ctx context.Context, identifyingCode PartyIdentifyingCode) (partyID string, err error)
}

// Common errors
var (
	ErrPartyNotFound = errors.New("party not found")
)

// NewPartyValidator creates a PartyValidator based on the configuration.
func NewPartyValidator(cfg *config.ServerEnvironment, queries *database.Queries) (PartyValidator, error) {
	switch cfg.PartyServiceName {
	case "local":
		// Use local admin endpoints
		return &PartyValidatorLocal{
			baseURL:    cfg.PartyServiceBaseURL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
		}, nil

	case "sample":
		// sample remote service (this is not a real service - illustration only)
		return &PartyValidatorSample{
			baseURL:    cfg.PartyServiceBaseURL,
			httpClient: &http.Client{Timeout: 10 * time.Second},
			// add authentication config as needed for your service
		}, nil

	default:
		return nil, fmt.Errorf("unsupported party service name: %s", cfg.PartyServiceName)
	}
}

// PartyValidatorLocal validates parties by calling the local admin GET parties endpoint
//
//	GET {baseURL}/admin/parties?codeListProvider={provider}&partyCode={code}
//	Response: {"id": "...", "partyName": "...", "active": true}
//	404 if party not found or inactive
type PartyValidatorLocal struct {
	baseURL    string
	httpClient *http.Client
}

// partyResponse represents the response from the admin GET /admin/parties endpoint
type partyResponse struct {
	ID        string `json:"id"`
	PartyName string `json:"partyName"`
	Active    bool   `json:"active"`
}

// callPartyService is a helper that calls the admin GET /admin/parties endpoint
func (h *PartyValidatorLocal) callPartyService(ctx context.Context, identifyingCode PartyIdentifyingCode) (*partyResponse, error) {
	// Build URL with query parameters
	u, err := url.Parse(h.baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	q := u.Query()
	q.Set("codeListProvider", identifyingCode.CodeListProvider)
	q.Set("partyCode", identifyingCode.PartyCode)
	if identifyingCode.CodeListName != nil {
		q.Set("codeListName", *identifyingCode.CodeListName)
	}
	u.RawQuery = q.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	// #nosec G704 -- False positive: BaseURL is from server config + query params are sanitized above (Encode()).
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call party service: %w", err)
	}
	defer resp.Body.Close()

	// Handle response
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrPartyNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("party service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var partyResp partyResponse
	if err := json.NewDecoder(resp.Body).Decode(&partyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &partyResp, nil
}

// ValidatePartyIdentifyingCode validates a party identifying code and returns the party name.
func (h *PartyValidatorLocal) ValidatePartyIdentifyingCode(ctx context.Context, identifyingCode PartyIdentifyingCode) (string, error) {
	partyResp, err := h.callPartyService(ctx, identifyingCode)
	if err != nil {
		return "", err
	}
	return partyResp.PartyName, nil
}

// GetPartyIDByIdentifyingCode returns the internal party ID for a given identifying code.
func (h *PartyValidatorLocal) GetPartyIDByIdentifyingCode(ctx context.Context, identifyingCode PartyIdentifyingCode) (string, error) {
	partyResp, err := h.callPartyService(ctx, identifyingCode)
	if err != nil {
		return "", err
	}
	return partyResp.ID, nil
}

// PartyValidatorSample validates parties by calling a remote service (illustrative example)
type PartyValidatorSample struct {
	baseURL    string
	httpClient *http.Client
}

// ValidatePartyIdentifyingCode validates a party by calling a remote service (illustrative example).
func (h *PartyValidatorSample) ValidatePartyIdentifyingCode(ctx context.Context, identifyingCode PartyIdentifyingCode) (string, error) {
	// implement remote service call here
	return "not implemented", nil
}

// GetPartyIDByIdentifyingCode returns the internal party ID by calling a remote service (illustrative example).
func (h *PartyValidatorSample) GetPartyIDByIdentifyingCode(ctx context.Context, identifyingCode PartyIdentifyingCode) (string, error) {
	// implement remote service call here
	return "not implemented", nil
}
