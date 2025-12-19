package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/information-sharing-networks/pint-demo/app/internal/config"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/server"
	"github.com/information-sharing-networks/pint-demo/app/internal/version"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// DCSA 3.0 PINT compatible receiver platform
func main() {
	cmd := &cobra.Command{
		Use:   "pint-receiver",
		Short: "PINT API receiver platform server",
		Long:  `PINT receiver platform implements the PINT API v3 for receiving eBL envelope transfers`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run()
		},
	}

	v := version.Get()
	cmd.Version = fmt.Sprintf("%s (built %s, commit %s)", v.Version, v.BuildDate, v.GitCommit)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.NewServerConfig()
	if err != nil {
		log.Printf("failed to load configuration: %v", err.Error())
		os.Exit(1)
	}

	appLogger := logger.InitLogger(logger.ParseLogLevel(cfg.LogLevel), cfg.Environment)

	appLogger.Info("Configuration loaded",
		slog.String("ENVIRONMENT", cfg.Environment),
		slog.String("HOST", cfg.Host),
		slog.Int("PORT", cfg.Port),
		slog.String("LOG_LEVEL", cfg.LogLevel),
		slog.Duration("READ_TIMEOUT", cfg.ReadTimeout),
		slog.Duration("WRITE_TIMEOUT", cfg.WriteTimeout),
		slog.Duration("IDLE_TIMEOUT", cfg.IdleTimeout),
		slog.Int("DB_MAX_CONNECTIONS", int(cfg.DBMaxConnections)),
		slog.Int("DB_MIN_CONNECTIONS", int(cfg.DBMinConnections)),
		slog.Duration("DB_MAX_CONN_LIFETIME", cfg.DBMaxConnLifetime),
		slog.Duration("DB_MAX_CONN_IDLE_TIME", cfg.DBMaxConnIdleTime),
		slog.Duration("DB_CONNECT_TIMEOUT", cfg.DBConnectTimeout),
	)

	dbCtx, dbCancel := context.WithTimeout(context.Background(), config.DatabasePingTimeout)
	defer dbCancel()

	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		appLogger.Error("Failed to parse database URL", slog.String("error", err.Error()))
		os.Exit(1)
	}

	poolConfig.MaxConns = cfg.DBMaxConnections
	poolConfig.MinConns = cfg.DBMinConnections
	poolConfig.MaxConnLifetime = cfg.DBMaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.DBMaxConnIdleTime
	poolConfig.ConnConfig.ConnectTimeout = cfg.DBConnectTimeout

	pool, err := pgxpool.NewWithConfig(dbCtx, poolConfig)
	if err != nil {
		appLogger.Error("Unable to create connection pool", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if err = pool.Ping(dbCtx); err != nil {
		appLogger.Error("Error pinging database via pool", slog.String("error", err.Error()))
		os.Exit(1)
	}

	appLogger.Info("connected to PostgreSQL")

	appLogger.Info("Starting server", slog.String("version", version.Get().Version))

	server := server.NewServer(
		pool,
		cfg,
		appLogger,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	defer server.DatabaseShutdown()

	if err := server.Start(ctx); err != nil {
		appLogger.Error("Server error", slog.String("error", err.Error()))
		return err
	}

	appLogger.Info("server shutdown complete")
	return nil
}
