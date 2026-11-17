package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vishalKami083/multitenant-usermgmt/internal/config"
	"github.com/vishalKami083/multitenant-usermgmt/internal/database"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpapi"
	"github.com/vishalKami083/multitenant-usermgmt/internal/repository"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := database.Open(ctx, cfg)
	if err != nil {
		logger.Error("connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool); err != nil {
		logger.Error("run database migrations", "error", err)
		os.Exit(1)
	}

	repo := repository.New(pool)
	tokens := security.NewTokenManager(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	app := service.New(repo, tokens, cfg.PermissionCacheTTL)
	go func() {
		if err := database.ListenPermissionCacheInvalidations(ctx, cfg.DatabaseURL, logger, app.InvalidatePermissionCache); err != nil {
			logger.Error("permission cache listener failed", "error", err)
			stop()
		}
	}()
	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           httpapi.New(app, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		logger.Info("server listening", "address", cfg.Address)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown failed", "error", err)
	}
}
