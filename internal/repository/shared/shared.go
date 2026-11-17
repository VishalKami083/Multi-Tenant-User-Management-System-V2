package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNotFound = errors.New("record not found")
	ErrConflict = errors.New("record already exists")
	ErrInvalid  = errors.New("invalid related record")
)

type Tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Status string `json:"status"`
}

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AuditEntry struct {
	ID         int64          `json:"id"`
	ActorID    *string        `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Details    map[string]any `json:"details"`
	CreatedAt  time.Time      `json:"created_at"`
}

type LoginRecord struct {
	TenantID         string
	TenantStatus     string
	UserID           string
	UserName         string
	Email            string
	PasswordHash     string
	MembershipStatus string
}

type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type RefreshedIdentity struct {
	TenantID string
	UserID   string
}

type execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func InsertAudit(ctx context.Context, e execer, tenantID, actorID, action, targetType, targetID string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	data, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = e.Exec(ctx, `INSERT INTO audit_logs(tenant_id,actor_id,action,target_type,target_id,details)
		VALUES($1,$2,$3,$4,$5,$6)`, tenantID, nullable(actorID), action, targetType, targetID, data)
	return err
}

func NormalizeError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrConflict
		case "23503", "23514", "22P02":
			return ErrInvalid
		}
	}
	return fmt.Errorf("database operation: %w", err)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
