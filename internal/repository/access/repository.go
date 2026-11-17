package accessrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vishalKami083/multitenant-usermgmt/internal/database"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type AccessRepository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *AccessRepository { return &AccessRepository{pool: pool} }

func (r *AccessRepository) Permissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT p.name FROM permissions p
		JOIN role_permissions rp ON rp.permission_id=p.id AND rp.tenant_id=$1
		JOIN membership_roles mr ON mr.tenant_id=rp.tenant_id AND mr.role_id=rp.role_id
		JOIN memberships m ON m.tenant_id=mr.tenant_id AND m.user_id=mr.user_id
		WHERE mr.user_id=$2 AND m.deleted_at IS NULL AND m.status='active'
		ORDER BY p.name`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var permissions []string
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, rows.Err()
}

func (r *AccessRepository) TenantActive(ctx context.Context, tenantID string) (bool, error) {
	var active bool
	err := r.pool.QueryRow(ctx, `SELECT status='active' FROM tenants WHERE id=$1`, tenantID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, repoData.ErrNotFound
	}
	return active, err
}

func (r *AccessRepository) ListRoles(ctx context.Context, tenantID string) ([]repoData.Role, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text,name,description FROM roles WHERE tenant_id=$1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]repoData.Role, 0)
	for rows.Next() {
		var role repoData.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *AccessRepository) ListPermissions(ctx context.Context) ([]repoData.Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT name,description FROM permissions ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	permissions := make([]repoData.Permission, 0)
	for rows.Next() {
		var permission repoData.Permission
		if err := rows.Scan(&permission.Name, &permission.Description); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, rows.Err()
}

func (r *AccessRepository) CreateRole(ctx context.Context, tenantID, actorID, name, description string) (repoData.Role, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return repoData.Role{}, err
	}
	defer tx.Rollback(ctx)
	var role repoData.Role
	err = tx.QueryRow(ctx, `INSERT INTO roles(tenant_id,name,description) VALUES($1,$2,$3)
		RETURNING id::text,name,description`, tenantID, name, description).Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		return repoData.Role{}, repoData.NormalizeError(err)
	}
	if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "role.created", "role", role.ID, map[string]any{"name": role.Name}); err != nil {
		return repoData.Role{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return repoData.Role{}, err
	}
	return role, nil
}

func (r *AccessRepository) AssignRole(ctx context.Context, tenantID, actorID, userID, roleID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `INSERT INTO membership_roles(tenant_id,user_id,role_id)
		SELECT $1,$2,$3 WHERE EXISTS (SELECT 1 FROM memberships WHERE tenant_id=$1 AND user_id=$2 AND deleted_at IS NULL)
		AND EXISTS (SELECT 1 FROM roles WHERE tenant_id=$1 AND id=$3) ON CONFLICT DO NOTHING`, tenantID, userID, roleID)
	if err != nil {
		return repoData.NormalizeError(err)
	}
	// A repeated assignment is idempotent; verify both IDs are members of this tenant.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN roles ro ON ro.tenant_id=m.tenant_id
		WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.deleted_at IS NULL AND ro.id=$3)`, tenantID, userID, roleID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return repoData.ErrNotFound
	}
	if tag.RowsAffected() > 0 {
		if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "role.assigned", "user", userID, map[string]any{"role_id": roleID}); err != nil {
			return err
		}
		if err := database.NotifyPermissionCacheInvalidation(ctx, tx, tenantID, userID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *AccessRepository) RemoveRole(ctx context.Context, tenantID, actorID, userID, roleID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM membership_roles mr USING memberships m
		WHERE mr.tenant_id=$1 AND mr.user_id=$2 AND mr.role_id=$3
		AND m.tenant_id=mr.tenant_id AND m.user_id=mr.user_id AND m.deleted_at IS NULL`, tenantID, userID, roleID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return repoData.ErrNotFound
	}
	if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "role.unassigned", "user", userID, map[string]any{"role_id": roleID}); err != nil {
		return err
	}
	if err := database.NotifyPermissionCacheInvalidation(ctx, tx, tenantID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *AccessRepository) SetRolePermissions(ctx context.Context, tenantID, actorID, roleID string, permissionNames []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE tenant_id=$1 AND id=$2)`, tenantID, roleID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return repoData.ErrNotFound
	}
	if _, err = tx.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2`, tenantID, roleID); err != nil {
		return err
	}
	for _, name := range permissionNames {
		tag, execErr := tx.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id)
			SELECT $1,$2,id FROM permissions WHERE name=$3 ON CONFLICT DO NOTHING`, tenantID, roleID, name)
		if execErr != nil {
			return execErr
		}
		if tag.RowsAffected() == 0 {
			return repoData.ErrInvalid
		}
	}
	if err = repoData.InsertAudit(ctx, tx, tenantID, actorID, "role.permissions_updated", "role", roleID,
		map[string]any{"permissions": permissionNames}); err != nil {
		return err
	}
	if err = database.NotifyPermissionCacheInvalidation(ctx, tx, tenantID, ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
