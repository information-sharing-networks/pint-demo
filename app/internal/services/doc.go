// Package services provides external service integrations for the PINT server.
//
// This package abstracts external dependencies (party validation, CTR, audit stores, etc.)
// to support both local implementations (dev/test) and remote services (production).
//
// Each service is defined as an interface with multiple implementations selected via configuration.
package services
