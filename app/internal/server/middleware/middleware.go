package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"golang.org/x/time/rate"

	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

// RequestSizeLimit returns a middleware that enforces a maximum request body size.
//
// the middleware immediately rejects requests where the Content-Length header is greater than the max size.
// Otherwise it reads the request body and returns a 413 if the body is too large
// (in case Content-Length is not set or incorrect)
//
// The middleware adds an X-Max-Request-Size header to all responses to inform clients
// of the server's size limit and returns 413 Payload Too Large if the request body is too large
func RequestSizeLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add informative header to all responses
			w.Header().Set("X-Max-Request-Size", strconv.FormatInt(maxBytes, 10))

			// Check Content-Length header for early rejection
			if r.ContentLength > maxBytes {
				err := pint.NewRequestTooLargeError(
					fmt.Sprintf("Request body size (%d bytes) exceeds maximum allowed size (%d bytes)", r.ContentLength, maxBytes),
				)
				pint.RespondWithErrorResponse(w, r, err)
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security-related headers to all responses
func SecurityHeaders(environment string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			if environment == "prod" || environment == "staging" {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit limits requests per second. If requestsPerSecond <= 0, rate limiting is disabled.
func RateLimit(requestsPerSecond int32, burst int32) func(http.Handler) http.Handler {
	// If rate limiting is disabled, return a no-op middleware
	if requestsPerSecond <= 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiter := rate.NewLimiter(rate.Limit(requestsPerSecond), int(burst))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				reqLogger := logger.ContextRequestLogger(r.Context())

				// Log rate limit violation immediately
				reqLogger.Warn("Rate limit exceeded",
					slog.String("component", "RateLimit"),
					slog.String("remote_addr", r.RemoteAddr),
				)

				// Add context for final request log
				logger.ContextWithLogAttrs(r.Context(),
					slog.String("remote_addr", r.RemoteAddr),
				)

				err := pint.NewRateLimitError("Too many requests. Please try again later.")
				pint.RespondWithErrorResponse(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
