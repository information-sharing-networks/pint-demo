package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRequestSizeLimits(t *testing.T) {
	router := chi.NewRouter()

	route := "/test/route"

	maxRequestSize := int64(64)

	errRequestSize := int64(128)

	if maxRequestSize <= 0 {
		t.Fatalf("Max request size is not greater than 0: %d", maxRequestSize)
	}

	router.Group(func(r chi.Router) {
		r.Use(RequestSizeLimit(maxRequestSize))
		r.Post(route, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	tests := []struct {
		name     string
		path     string
		bodySize int64
		wantCode int
	}{
		// API endpoints (64KB limit)
		{"API normal request", route, maxRequestSize, http.StatusOK},
		{"API oversized request", route, errRequestSize, 413}, // Request Entity Too Large
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.Repeat("x", int(tt.bodySize))
			req := httptest.NewRequest("POST", tt.path, bytes.NewReader([]byte(body)))
			req.ContentLength = tt.bodySize

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", rr.Code, tt.wantCode)
			}

			// Verify header is always set
			if header := rr.Header().Get("X-Max-Request-Size"); header == "" {
				t.Error("X-Max-Request-Size header not set")
			}
		})
	}
}

func TestRateLimitIsEnabled(t *testing.T) {
	// Create router with rate limiting
	router := chi.NewRouter()
	router.Use(RateLimit(10, 5)) // 10 requests per second, burst of 5
	router.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First few requests should succeed (within burst)
	for i := range 5 {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Request %d failed: got status %d, want %d", i+1, rr.Code, http.StatusOK)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Rate limit request should fail: got status %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

func TestRateLimitIsDisabled(t *testing.T) {

	tests := []struct {
		name          string
		rps           int32
		expectLimited bool
	}{
		{"Rate limiting enabled", 10, true},
		{"Rate limiting disabled with 0", 0, false},
		{"Rate limiting disabled with negative", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := chi.NewRouter()
			router.Use(RateLimit(tt.rps, 1)) // burst of 1 for easy testing
			router.Get("/test", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Make 2 requests quickly
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				rr := httptest.NewRecorder()
				router.ServeHTTP(rr, req)

				if tt.expectLimited && i == 1 {
					// Second request should be rate limited
					if rr.Code != http.StatusTooManyRequests {
						t.Errorf("Expected rate limit on request %d: got status %d, want %d", i+1, rr.Code, http.StatusTooManyRequests)
					}
				} else {
					// Request should succeed
					if rr.Code != http.StatusOK {
						t.Errorf("Request %d failed: got status %d, want %d", i+1, rr.Code, http.StatusOK)
					}
				}
			}
		})
	}
}
