package membershiprepo

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vishalKami083/multitenant-usermgmt/internal/database"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type MembershipRepository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *MembershipRepository {
	return &MembershipRepository{pool: pool}
}

func (r *MembershipRepository) AddMembership(ctx context.Context, tenantID, actorID, userID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `INSERT INTO memberships(tenant_id,user_id,display_name)
		SELECT $1,id,name FROM users WHERE id=$2
		ON CONFLICT (tenant_id,user_id) DO UPDATE SET display_name=EXCLUDED.display_name,status='active',deleted_at=NULL
		WHERE memberships.deleted_at IS NOT NULL`, tenantID, userID)
	if err != nil {
		return repoData.NormalizeError(err)
	}
	if tag.RowsAffected() == 0 {
		var userExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, userID).Scan(&userExists); err != nil {
			return err
		}
		if userExists {
			return repoData.ErrConflict
		}
		return repoData.ErrNotFound
	}
	if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "membership.created", "user", userID, nil); err != nil {
		return err
	}
	if err := database.NotifyPermissionCacheInvalidation(ctx, tx, tenantID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *MembershipRepository) UpdateMembershipStatus(ctx context.Context, tenantID, actorID, userID, status string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `UPDATE memberships SET status=$3
		WHERE tenant_id=$1 AND user_id=$2 AND deleted_at IS NULL AND status<>$3`,
		tenantID, userID, status)
	if err != nil {
		return repoData.NormalizeError(err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships
			WHERE tenant_id=$1 AND user_id=$2 AND deleted_at IS NULL)`, tenantID, userID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return repoData.ErrNotFound
		}
		return tx.Commit(ctx)
	}
	if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "membership.status_updated", "user", userID,
		map[string]any{"status": status}); err != nil {
		return err
	}
	if err := database.NotifyPermissionCacheInvalidation(ctx, tx, tenantID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
