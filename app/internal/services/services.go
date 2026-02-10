package services

// services provides external service integrations for the PINT server (CTR, party validation etc.)

import (
	"github.com/information-sharing-networks/pint-demo/app/internal/config"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
)

// Services aggregates all external service integrations used by the PINT server.
type Services struct {
	PartyValidator PartyValidator
	// Future: CTRClient, Notary client, etc
}

// NewServices creates service implementations based on configuration.
// This is the single entry point for initializing all external service integrations.
func NewServices(cfg *config.ServerEnvironment, queries *database.Queries) (*Services, error) {

	s := &Services{}
	if partyValidator, err := NewPartyValidator(cfg, queries); err != nil {
		return nil, err
	} else {
		s.PartyValidator = partyValidator
	}
	return s, nil
}
