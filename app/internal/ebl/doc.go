// Package ebl provides high-level functions for creating DCSA PINT API requests.
//
// These functions are used by the HTTP server to handle PINT API (envelope transfer) requests.
//
// Note: Because these functions rely heavily on the crypto package, bugs in the low level crypto package
// will cause cascading test failures here. Fix the crypto issues first, then ebl failures.
package ebl
