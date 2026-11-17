package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const permissionCacheInvalidationChannel = "permission_cache_invalidation"

type permissionCacheInvalidation struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id,omitempty"`
}

func NotifyPermissionCacheInvalidation(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	if tenantID == "" {
		return errors.New("tenant ID is required for permission cache invalidation")
	}
	payload, err := json.Marshal(permissionCacheInvalidation{TenantID: tenantID, UserID: userID})
	if err != nil {
		return fmt.Errorf("encode permission cache invalidation: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, permissionCacheInvalidationChannel, string(payload)); err != nil {
		return fmt.Errorf("publish permission cache invalidation: %w", err)
	}
	return nil
}

func ListenPermissionCacheInvalidations(
	ctx context.Context,
	databaseURL string,
	logger *slog.Logger,
	invalidate func(tenantID, userID string),
) error {
	if databaseURL == "" {
		return errors.New("database URL is required for permission cache invalidation listener")
	}
	if logger == nil {
		return errors.New("logger is required for permission cache invalidation listener")
	}
	if invalidate == nil {
		return errors.New("invalidation handler is required")
	}

	retryDelay := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := listenPermissionCacheInvalidations(ctx, databaseURL, logger, invalidate)
		if ctx.Err() != nil {
			return nil
		}

		logger.WarnContext(ctx, "permission cache listener disconnected",
			"error", err, "retry_delay", retryDelay)
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
		if retryDelay < 30*time.Second {
			retryDelay *= 2
			if retryDelay > 30*time.Second {
				retryDelay = 30 * time.Second
			}
		}
	}
}

func listenPermissionCacheInvalidations(
	ctx context.Context,
	databaseURL string,
	logger *slog.Logger,
	invalidate func(tenantID, userID string),
) error {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect permission cache listener: %w", err)
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+permissionCacheInvalidationChannel); err != nil {
		return fmt.Errorf("listen for permission cache invalidations: %w", err)
	}

	// Reconcile changes that may have been published while this listener was offline.
	invalidate("", "")
	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("wait for permission cache invalidation: %w", err)
		}
		var event permissionCacheInvalidation
		if err := json.Unmarshal([]byte(notification.Payload), &event); err != nil {
			logger.ErrorContext(ctx, "discard malformed permission cache invalidation", "error", err)
			continue
		}
		if event.TenantID == "" {
			logger.ErrorContext(ctx, "discard permission cache invalidation without tenant ID")
			continue
		}
		invalidate(event.TenantID, event.UserID)
	}
}
