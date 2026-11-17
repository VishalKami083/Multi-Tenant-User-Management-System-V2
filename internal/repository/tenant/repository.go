package tenantrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vishalKami083/multitenant-usermgmt/internal/database"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type TenantRepository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *TenantRepository { return &TenantRepository{pool: pool} }

func (r *TenantRepository) CreateTenant(ctx context.Context, name, code, ownerName, email, passwordHash string) (repoData.Tenant, repoData.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	defer tx.Rollback(ctx)

	var tenant repoData.Tenant
	err = tx.QueryRow(ctx, `INSERT INTO tenants(name, code) VALUES($1,$2) RETURNING id::text,name,code,status`, name, code).
		Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status)
	if err != nil {
		return repoData.Tenant{}, repoData.User{}, repoData.NormalizeError(err)
	}
	var user repoData.User
	err = tx.QueryRow(ctx, `INSERT INTO users(name,email,password_hash) VALUES($1,lower($2),$3) RETURNING id::text,name,email,created_at`,
		ownerName, email, passwordHash).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if err != nil {
		return repoData.Tenant{}, repoData.User{}, repoData.NormalizeError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(tenant_id,user_id,display_name) VALUES($1,$2,$3)`,
		tenant.ID, user.ID, ownerName); err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	var roleID string
	if err = tx.QueryRow(ctx, `INSERT INTO roles(tenant_id,name,description) VALUES($1,'admin','Tenant administrator') RETURNING id::text`, tenant.ID).Scan(&roleID); err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id)
		SELECT $1,$2,id FROM permissions`, tenant.ID, roleID); err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO membership_roles(tenant_id,user_id,role_id) VALUES($1,$2,$3)`, tenant.ID, user.ID, roleID); err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	if err = repoData.InsertAudit(ctx, tx, tenant.ID, user.ID, "tenant.created", "tenant", tenant.ID, map[string]any{"code": code}); err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	if err = repoData.InsertAudit(ctx, tx, tenant.ID, user.ID, "user.created", "user", user.ID, map[string]any{"email": user.Email, "bootstrap_owner": true}); err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	return tenant, user, nil
}

func (r *TenantRepository) GetTenant(ctx context.Context, tenantID string) (repoData.Tenant, error) {
	var tenant repoData.Tenant
	err := r.pool.QueryRow(ctx, `SELECT id::text,name,code,status FROM tenants WHERE id=$1`, tenantID).
		Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoData.Tenant{}, repoData.ErrNotFound
	}
	return tenant, err
}

func (r *TenantRepository) UpdateTenant(ctx context.Context, tenantID, actorID, name, code, status string) (repoData.Tenant, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return repoData.Tenant{}, err
	}
	defer tx.Rollback(ctx)
	var tenant repoData.Tenant
	err = tx.QueryRow(ctx, `UPDATE tenants SET name=$2,code=$3,status=$4,updated_at=now() WHERE id=$1
		RETURNING id::text,name,code,status`, tenantID, name, code, status).
		Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoData.Tenant{}, repoData.ErrNotFound
	}
	if err != nil {
		return repoData.Tenant{}, repoData.NormalizeError(err)
	}
	if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "tenant.updated", "tenant", tenantID,
		map[string]any{"name": name, "code": code, "status": status}); err != nil {
		return repoData.Tenant{}, err
	}
	if err := database.NotifyPermissionCacheInvalidation(ctx, tx, tenantID, ""); err != nil {
		return repoData.Tenant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return repoData.Tenant{}, err
	}
	return tenant, nil
}
