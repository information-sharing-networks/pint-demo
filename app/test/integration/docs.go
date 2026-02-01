// Package integration contains end-to-end tests for the PINT API server.
//
// These tests verify the server handles API requests correctly (expected responses,
// error handling, database persistence, etc). Each test runs against a temporary
// database with migrations applied, and the server is started in-process.
//
// These tests assume the crypto and ebl packages are working correctly (tested separately).
// If bugs are introduced in lower-level packages, there will be cascading failures here -
// fix the low-level problems first.
package integration
