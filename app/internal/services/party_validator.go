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

// PartyValidator validates party identifying codes and returns party information.
type PartyValidator interface {
	// ValidateReceiver validates a party identifying code and returns the party name if found and active.
	// Returns ErrPartyNotFound if the party is not found, inactive, or the code list provider is not supported.
	ValidateReceiver(ctx context.Context, codeListProvider, partyCode string) (partyName string, err error)
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
//	GET {baseURL}/admin/parties?code_list_provider={provider}&party_code={code}
//	Response: {"party_name": "...", ...}
//	404 if party not found or inactive
type PartyValidatorLocal struct {
	baseURL    string
	httpClient *http.Client
}

// ValidateReceiver validates a party by calling GET /admin/parties with query parameters.
func (h *PartyValidatorLocal) ValidateReceiver(ctx context.Context, codeListProvider, partyCode string) (string, error) {
	// Build URL with query parameters
	u, err := url.Parse(h.baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL: %w", err)
	}

	q := u.Query()
	q.Set("code_list_provider", codeListProvider)
	q.Set("party_code", partyCode)
	u.RawQuery = q.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	// #nosec G704 -- False positive: BaseURL is from server config + query params are sanitized above (Encode()).
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call party service: %w", err)
	}
	defer resp.Body.Close()

	// Handle response
	if resp.StatusCode == http.StatusNotFound {
		return "", ErrPartyNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("party service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var partyResp struct {
		PartyName string `json:"party_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&partyResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return partyResp.PartyName, nil
}

// PartyValidatorSample validates parties by calling a remote service (illustrative example)
type PartyValidatorSample struct {
	baseURL    string
	httpClient *http.Client
}

// ValidateReceiver validates a party by calling GET /admin/parties with query parameters.
func (h *PartyValidatorSample) ValidateReceiver(ctx context.Context, codeListProvider, partyCode string) (string, error) {
	// implement remote service call here
	return "not implemented", nil
}
