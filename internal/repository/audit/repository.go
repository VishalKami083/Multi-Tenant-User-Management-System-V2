package auditrepo

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type AuditRepository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *AuditRepository { return &AuditRepository{pool: pool} }

func (r *AuditRepository) AuditLogs(ctx context.Context, tenantID string, limit, offset int) ([]repoData.AuditEntry, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,actor_id::text,action,target_type,target_id,details,created_at
		FROM audit_logs WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]repoData.AuditEntry, 0)
	for rows.Next() {
		var entry repoData.AuditEntry
		var details []byte
		if err := rows.Scan(&entry.ID, &entry.ActorID, &entry.Action, &entry.TargetType, &entry.TargetID, &details, &entry.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(details, &entry.Details); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (r *AuditRepository) RecordLogin(ctx context.Context, tenantID, userID string) error {
	return repoData.InsertAudit(ctx, r.pool, tenantID, userID, "auth.login", "user", userID, nil)
}

func (r *AuditRepository) RecordFailedLogin(ctx context.Context, tenantCode string) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO audit_logs(tenant_id,action,target_type,target_id,details)
		SELECT id,'auth.login_failed','authentication','', '{}'::jsonb
		FROM tenants WHERE code=$1`, tenantCode)
	return err
}
