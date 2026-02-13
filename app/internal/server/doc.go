// Package server provides the HTTP server for the PINT demo app.
//
// the server is configured through environment variables
// (see app/internal/config/config.go for details)
//
// The package includes the handlers for
//   - common infrastructure handlers (health, version, jwks, docs etc)
//   - the admin API for managing parties and party codes.
//
// middleware is in app/internal/server/middleware
package server
