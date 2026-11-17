package authrepo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type AuthRepository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *AuthRepository { return &AuthRepository{pool: pool} }

func (r *AuthRepository) FindLogin(ctx context.Context, tenantCode, email string) (repoData.LoginRecord, error) {
	var rec repoData.LoginRecord
	err := r.pool.QueryRow(ctx, `SELECT t.id::text,t.status,u.id::text,u.name,u.email,u.password_hash,m.status
		FROM tenants t JOIN memberships m ON m.tenant_id=t.id AND m.deleted_at IS NULL
		JOIN users u ON u.id=m.user_id WHERE t.code=$1 AND lower(u.email)=lower($2)`,
		tenantCode, email).Scan(&rec.TenantID, &rec.TenantStatus, &rec.UserID, &rec.UserName, &rec.Email, &rec.PasswordHash, &rec.MembershipStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoData.LoginRecord{}, repoData.ErrNotFound
	}
	return rec, err
}

func (r *AuthRepository) StoreRefresh(ctx context.Context, tokenHash []byte, tenantID, userID string, expires time.Time) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO refresh_tokens(token_hash,tenant_id,user_id,expires_at) VALUES($1,$2,$3,$4)`,
		tokenHash, tenantID, userID, expires)
	return err
}

func (r *AuthRepository) RefreshIdentity(ctx context.Context, tokenHash []byte, now time.Time) (repoData.RefreshedIdentity, error) {
	var identity repoData.RefreshedIdentity
	err := r.pool.QueryRow(ctx, `SELECT rt.tenant_id::text,rt.user_id::text FROM refresh_tokens rt
		JOIN tenants t ON t.id=rt.tenant_id AND t.status='active'
		JOIN memberships m ON m.tenant_id=rt.tenant_id AND m.user_id=rt.user_id
		WHERE rt.token_hash=$1 AND rt.revoked_at IS NULL AND rt.expires_at>$2
		AND m.status='active' AND m.deleted_at IS NULL`, tokenHash, now).
		Scan(&identity.TenantID, &identity.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoData.RefreshedIdentity{}, repoData.ErrNotFound
	}
	return identity, err
}

func (r *AuthRepository) RotateRefresh(ctx context.Context, oldHash, newHash []byte, now, newExpiry time.Time) (repoData.RefreshedIdentity, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return repoData.RefreshedIdentity{}, err
	}
	defer tx.Rollback(ctx)
	var identity repoData.RefreshedIdentity
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,user_id::text FROM refresh_tokens
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>$2 FOR UPDATE`, oldHash, now).
		Scan(&identity.TenantID, &identity.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoData.RefreshedIdentity{}, repoData.ErrNotFound
	}
	if err != nil {
		return repoData.RefreshedIdentity{}, err
	}
	tag, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE token_hash=$1 AND revoked_at IS NULL`, oldHash, now)
	if err != nil {
		return repoData.RefreshedIdentity{}, err
	}
	if tag.RowsAffected() != 1 {
		return repoData.RefreshedIdentity{}, repoData.ErrNotFound
	}
	tag, err = tx.Exec(ctx, `INSERT INTO refresh_tokens(token_hash,tenant_id,user_id,expires_at)
		SELECT $1,$2,$3,$4 WHERE EXISTS (
			SELECT 1 FROM tenants t JOIN memberships m ON m.tenant_id=t.id
			WHERE t.id=$2 AND t.status='active' AND m.user_id=$3 AND m.status='active' AND m.deleted_at IS NULL)`,
		newHash, identity.TenantID, identity.UserID, newExpiry)
	if err != nil {
		return repoData.RefreshedIdentity{}, err
	}
	if tag.RowsAffected() != 1 {
		return repoData.RefreshedIdentity{}, repoData.ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return repoData.RefreshedIdentity{}, err
	}
	return identity, nil
}

func (r *AuthRepository) RevokeRefresh(ctx context.Context, tokenHash []byte, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE token_hash=$1 AND revoked_at IS NULL`, tokenHash, now)
	return err
}
