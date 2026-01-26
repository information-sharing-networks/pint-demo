package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/information-sharing-networks/pint-demo/app/internal/config"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint/handlers"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	pool       *pgxpool.Pool
	queries    *database.Queries
	config     *config.ServerEnvironment
	logger     *slog.Logger
	router     *chi.Mux
	keyManager *pint.KeyManager
	signingKey any // Ed22519.PrivateKey or *rsa.PrivateKey
}

func NewServer(
	pool *pgxpool.Pool,
	queries *database.Queries,
	cfg *config.ServerEnvironment,
	logger *slog.Logger,
	ctx context.Context,
) (*Server, error) {
	server := &Server{
		pool:   pool,
		config: cfg,
		logger: logger,
		router: chi.NewRouter(),
	}

	// load signing key
	signingKey, err := crypto.ReadPrivateKeyFromJWKFile(cfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key: %w", err)
	}

	server.signingKey = signingKey
	if err := server.initKeyManager(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize KeyManager: %w", err)
	}

	// setup middleware and routes
	server.setupMiddleware()
	server.registerRoutes()

	return server, nil
}

// initKeyManager creates and initializes the KeyManager.
func (s *Server) initKeyManager(ctx context.Context) error {

	s.logger.Info("DCSA registry URL",
		slog.String("url", s.config.RegistryPath))

	keyManagerConfig := pint.NewKeymanagerConfig(
		s.config.RegistryPath,
		s.config.ManualKeysDir,
		s.config.JWKCacheHTTPTimeout,
		s.config.SkipJWKCache,
		s.config.JWKCacheMinRefresh,
		s.config.JWKCacheMaxRefresh,
	)

	kmCtx, cancel := context.WithTimeout(ctx, s.config.RegistryFetchTimeout)
	defer cancel()

	keyManager, err := pint.NewKeyManager(kmCtx, keyManagerConfig, s.logger)
	if err != nil {
		return fmt.Errorf("failed to create KeyManager: %w", err)
	}

	s.keyManager = keyManager
	s.logger.Info("KeyManager initialized successfully")

	return nil
}

func (s *Server) setupMiddleware() {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Recoverer)
	// TODO: handle timeouts
	//s.router.Use(middleware.Timeout(60 * time.Second))
}

func (s *Server) registerRoutes() {

	s.router.Get("/health", s.handleHealth)

	// Create handlers with dependencies
	startTransferHandler := handlers.NewStartTransferHandler(s.queries, s.keyManager, s.config.SigningKeyPath)

	s.router.Route("/v3", func(r chi.Router) {
		r.Post("/receiver-validation", s.handleReceiverValidation)
		r.Post("/envelopes", startTransferHandler.HandleStartTransfer)
		r.Put("/envelopes/{envelopeReference}/additional-documents/{documentChecksum}", s.handleTransferAdditionalDocument)
		r.Put("/envelopes/{envelopeReference}/finish-transfer", s.handleFinishEnvelopeTransfer)
	})

	s.router.Get("/.well-known/jwks.json", s.handleJWKS)
}

func (s *Server) Start(ctx context.Context) error {
	serverAddr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	httpServer := &http.Server{
		Addr:         serverAddr,
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	serverErrors := make(chan error, 1)

	go func() {
		s.logger.Info("service listening",
			slog.String("environment", s.config.Environment),
			slog.String("address", serverAddr))

		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			serverErrors <- fmt.Errorf("server failed to start: %w", err)
		}
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
		s.logger.Info("shutdown signal received")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), s.config.ServerShutdownTimeout)
	defer shutdownCancel()

	s.logger.Info("shutting down HTTP server")

	err := httpServer.Shutdown(shutdownCtx)
	if err != nil {
		s.logger.Warn("HTTP server shutdown error",
			slog.String("error", err.Error()))
		return fmt.Errorf("HTTP server shutdown failed: %w", err)
	}

	s.logger.Info("HTTP server shutdown complete")
	return nil
}

func (s *Server) DatabaseShutdown() {
	if s.pool != nil {
		s.pool.Close()
		s.logger.Info("database connection closed")
	}
}

// TODO - c.f signalsd
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy"}`))
}

func (s *Server) handleReceiverValidation(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleTransferAdditionalDocument(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleFinishEnvelopeTransfer(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// handleJWKS serves the JSON Web Key Set at /.well-known/jwks.json
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}
