package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("record not found")
	ErrConflict = errors.New("record already exists")
	ErrInvalid  = errors.New("invalid related record")
)

type Repository struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

func (r *Repository) CreateTenant(ctx context.Context, name, code, ownerName, email, passwordHash string) (Tenant, User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Tenant{}, User{}, err
	}
	defer tx.Rollback(ctx)

	var tenant Tenant
	err = tx.QueryRow(ctx, `INSERT INTO tenants(name, code) VALUES($1,$2) RETURNING id::text,name,code,status`, name, code).
		Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status)
	if err != nil {
		return Tenant{}, User{}, normalizeError(err)
	}
	var user User
	err = tx.QueryRow(ctx, `INSERT INTO users(name,email,password_hash) VALUES($1,lower($2),$3) RETURNING id::text,name,email,created_at`,
		ownerName, email, passwordHash).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if err != nil {
		return Tenant{}, User{}, normalizeError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(tenant_id,user_id,display_name) VALUES($1,$2,$3)`,
		tenant.ID, user.ID, ownerName); err != nil {
		return Tenant{}, User{}, err
	}
	var roleID string
	if err = tx.QueryRow(ctx, `INSERT INTO roles(tenant_id,name,description) VALUES($1,'admin','Tenant administrator') RETURNING id::text`, tenant.ID).Scan(&roleID); err != nil {
		return Tenant{}, User{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id)
		SELECT $1,$2,id FROM permissions`, tenant.ID, roleID); err != nil {
		return Tenant{}, User{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO membership_roles(tenant_id,user_id,role_id) VALUES($1,$2,$3)`, tenant.ID, user.ID, roleID); err != nil {
		return Tenant{}, User{}, err
	}
	if err = insertAudit(ctx, tx, tenant.ID, user.ID, "tenant.created", "tenant", tenant.ID, map[string]any{"code": code}); err != nil {
		return Tenant{}, User{}, err
	}
	if err = insertAudit(ctx, tx, tenant.ID, user.ID, "user.created", "user", user.ID, map[string]any{"email": user.Email, "bootstrap_owner": true}); err != nil {
		return Tenant{}, User{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Tenant{}, User{}, err
	}
	return tenant, user, nil
}

func (r *Repository) FindLogin(ctx context.Context, tenantCode, email string) (LoginRecord, error) {
	var rec LoginRecord
	err := r.pool.QueryRow(ctx, `SELECT t.id::text,t.status,u.id::text,u.name,u.email,u.password_hash,m.status
		FROM tenants t JOIN memberships m ON m.tenant_id=t.id AND m.deleted_at IS NULL
		JOIN users u ON u.id=m.user_id WHERE t.code=$1 AND lower(u.email)=lower($2)`,
		tenantCode, email).Scan(&rec.TenantID, &rec.TenantStatus, &rec.UserID, &rec.UserName, &rec.Email, &rec.PasswordHash, &rec.MembershipStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginRecord{}, ErrNotFound
	}
	return rec, err
}

func (r *Repository) StoreRefresh(ctx context.Context, tokenHash []byte, tenantID, userID string, expires time.Time) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO refresh_tokens(token_hash,tenant_id,user_id,expires_at) VALUES($1,$2,$3,$4)`,
		tokenHash, tenantID, userID, expires)
	return err
}

func (r *Repository) RefreshIdentity(ctx context.Context, tokenHash []byte, now time.Time) (RefreshedIdentity, error) {
	var identity RefreshedIdentity
	err := r.pool.QueryRow(ctx, `SELECT rt.tenant_id::text,rt.user_id::text FROM refresh_tokens rt
		JOIN tenants t ON t.id=rt.tenant_id AND t.status='active'
		JOIN memberships m ON m.tenant_id=rt.tenant_id AND m.user_id=rt.user_id
		WHERE rt.token_hash=$1 AND rt.revoked_at IS NULL AND rt.expires_at>$2
		AND m.status='active' AND m.deleted_at IS NULL`, tokenHash, now).
		Scan(&identity.TenantID, &identity.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshedIdentity{}, ErrNotFound
	}
	return identity, err
}

func (r *Repository) RotateRefresh(ctx context.Context, oldHash, newHash []byte, now, newExpiry time.Time) (RefreshedIdentity, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return RefreshedIdentity{}, err
	}
	defer tx.Rollback(ctx)
	var identity RefreshedIdentity
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,user_id::text FROM refresh_tokens
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>$2 FOR UPDATE`, oldHash, now).
		Scan(&identity.TenantID, &identity.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshedIdentity{}, ErrNotFound
	}
	if err != nil {
		return RefreshedIdentity{}, err
	}
	tag, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE token_hash=$1 AND revoked_at IS NULL`, oldHash, now)
	if err != nil {
		return RefreshedIdentity{}, err
	}
	if tag.RowsAffected() != 1 {
		return RefreshedIdentity{}, ErrNotFound
	}
	tag, err = tx.Exec(ctx, `INSERT INTO refresh_tokens(token_hash,tenant_id,user_id,expires_at)
		SELECT $1,$2,$3,$4 WHERE EXISTS (
			SELECT 1 FROM tenants t JOIN memberships m ON m.tenant_id=t.id
			WHERE t.id=$2 AND t.status='active' AND m.user_id=$3 AND m.status='active' AND m.deleted_at IS NULL)`,
		newHash, identity.TenantID, identity.UserID, newExpiry)
	if err != nil {
		return RefreshedIdentity{}, err
	}
	if tag.RowsAffected() != 1 {
		return RefreshedIdentity{}, ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return RefreshedIdentity{}, err
	}
	return identity, nil
}

func (r *Repository) RevokeRefresh(ctx context.Context, tokenHash []byte, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE token_hash=$1 AND revoked_at IS NULL`, tokenHash, now)
	return err
}

func (r *Repository) Permissions(ctx context.Context, tenantID, userID string) ([]string, error) {
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

func (r *Repository) TenantActive(ctx context.Context, tenantID string) (bool, error) {
	var active bool
	err := r.pool.QueryRow(ctx, `SELECT status='active' FROM tenants WHERE id=$1`, tenantID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return active, err
}

func (r *Repository) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	var tenant Tenant
	err := r.pool.QueryRow(ctx, `SELECT id::text,name,code,status FROM tenants WHERE id=$1`, tenantID).
		Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return tenant, err
}

func (r *Repository) UpdateTenant(ctx context.Context, tenantID, actorID, name, code, status string) (Tenant, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Tenant{}, err
	}
	defer tx.Rollback(ctx)
	var tenant Tenant
	err = tx.QueryRow(ctx, `UPDATE tenants SET name=$2,code=$3,status=$4,updated_at=now() WHERE id=$1
		RETURNING id::text,name,code,status`, tenantID, name, code, status).
		Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, normalizeError(err)
	}
	if err := insertAudit(ctx, tx, tenantID, actorID, "tenant.updated", "tenant", tenantID,
		map[string]any{"name": name, "code": code, "status": status}); err != nil {
		return Tenant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Tenant{}, err
	}
	return tenant, nil
}

func (r *Repository) ListUsers(ctx context.Context, tenantID, search string, limit, offset int) ([]User, int, error) {
	search = "%" + strings.ToLower(search) + "%"
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id
		WHERE m.tenant_id=$1 AND m.status='active' AND m.deleted_at IS NULL
		AND ($2='%%' OR lower(COALESCE(m.display_name,u.name)) LIKE $2 OR lower(u.email) LIKE $2)`,
		tenantID, search).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT u.id::text,COALESCE(m.display_name,u.name),u.email,u.created_at FROM memberships m
		JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.status='active' AND m.deleted_at IS NULL
		AND ($2='%%' OR lower(COALESCE(m.display_name,u.name)) LIKE $2 OR lower(u.email) LIKE $2)
		ORDER BY u.created_at DESC,u.id LIMIT $3 OFFSET $4`, tenantID, search, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt); err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	return users, total, rows.Err()
}

func (r *Repository) GetUser(ctx context.Context, tenantID, userID string) (User, error) {
	var user User
	err := r.pool.QueryRow(ctx, `SELECT u.id::text,COALESCE(m.display_name,u.name),u.email,u.created_at FROM users u
		JOIN memberships m ON m.user_id=u.id WHERE m.tenant_id=$1 AND m.user_id=$2
		AND m.status='active' AND m.deleted_at IS NULL`,
		tenantID, userID).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return user, err
}

func (r *Repository) CreateUser(ctx context.Context, tenantID, actorID, name, email, hash string) (User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	var user User
	err = tx.QueryRow(ctx, `INSERT INTO users(name,email,password_hash) VALUES($1,lower($2),$3)
		RETURNING id::text,name,email,created_at`, name, email, hash).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if err != nil {
		return User{}, normalizeError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(tenant_id,user_id,display_name) VALUES($1,$2,$3)`,
		tenantID, user.ID, name); err != nil {
		return User{}, normalizeError(err)
	}
	if err = insertAudit(ctx, tx, tenantID, actorID, "user.created", "user", user.ID, map[string]any{"email": user.Email}); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return user, nil
}

func (r *Repository) AddMembership(ctx context.Context, tenantID, actorID, userID string) error {
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
		return normalizeError(err)
	}
	if tag.RowsAffected() == 0 {
		var userExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, userID).Scan(&userExists); err != nil {
			return err
		}
		if userExists {
			return ErrConflict
		}
		return ErrNotFound
	}
	if err := insertAudit(ctx, tx, tenantID, actorID, "membership.created", "user", userID, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repository) UpdateUser(ctx context.Context, tenantID, actorID, userID, name string) (User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	var user User
	err = tx.QueryRow(ctx, `UPDATE memberships m SET display_name=$3 FROM users u
		WHERE m.tenant_id=$1 AND m.user_id=u.id AND m.user_id=$2 AND m.deleted_at IS NULL
		RETURNING u.id::text,m.display_name,u.email,u.created_at`, tenantID, userID, name).
		Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if err := insertAudit(ctx, tx, tenantID, actorID, "user.updated", "user", userID, map[string]any{"name": name}); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return user, nil
}

func (r *Repository) DeleteUser(ctx context.Context, tenantID, actorID, userID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE memberships SET deleted_at=now() WHERE tenant_id=$1 AND user_id=$2 AND deleted_at IS NULL`,
		tenantID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM membership_roles WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, tenantID, actorID, "user.deleted", "user", userID, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repository) ListRoles(ctx context.Context, tenantID string) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text,name,description FROM roles WHERE tenant_id=$1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]Role, 0)
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *Repository) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT name,description FROM permissions ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	permissions := make([]Permission, 0)
	for rows.Next() {
		var permission Permission
		if err := rows.Scan(&permission.Name, &permission.Description); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, rows.Err()
}

func (r *Repository) CreateRole(ctx context.Context, tenantID, actorID, name, description string) (Role, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Role{}, err
	}
	defer tx.Rollback(ctx)
	var role Role
	err = tx.QueryRow(ctx, `INSERT INTO roles(tenant_id,name,description) VALUES($1,$2,$3)
		RETURNING id::text,name,description`, tenantID, name, description).Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		return Role{}, normalizeError(err)
	}
	if err := insertAudit(ctx, tx, tenantID, actorID, "role.created", "role", role.ID, map[string]any{"name": role.Name}); err != nil {
		return Role{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Role{}, err
	}
	return role, nil
}

func (r *Repository) AssignRole(ctx context.Context, tenantID, actorID, userID, roleID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `INSERT INTO membership_roles(tenant_id,user_id,role_id)
		SELECT $1,$2,$3 WHERE EXISTS (SELECT 1 FROM memberships WHERE tenant_id=$1 AND user_id=$2 AND deleted_at IS NULL)
		AND EXISTS (SELECT 1 FROM roles WHERE tenant_id=$1 AND id=$3) ON CONFLICT DO NOTHING`, tenantID, userID, roleID)
	if err != nil {
		return normalizeError(err)
	}
	// A repeated assignment is idempotent; verify both IDs are members of this tenant.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN roles ro ON ro.tenant_id=m.tenant_id
		WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.deleted_at IS NULL AND ro.id=$3)`, tenantID, userID, roleID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if tag.RowsAffected() > 0 {
		if err := insertAudit(ctx, tx, tenantID, actorID, "role.assigned", "user", userID, map[string]any{"role_id": roleID}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *Repository) RemoveRole(ctx context.Context, tenantID, actorID, userID, roleID string) error {
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
		return ErrNotFound
	}
	if err := insertAudit(ctx, tx, tenantID, actorID, "role.unassigned", "user", userID, map[string]any{"role_id": roleID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repository) SetRolePermissions(ctx context.Context, tenantID, actorID, roleID string, permissionNames []string) error {
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
		return ErrNotFound
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
			return ErrInvalid
		}
	}
	if err = insertAudit(ctx, tx, tenantID, actorID, "role.permissions_updated", "role", roleID,
		map[string]any{"permissions": permissionNames}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repository) AuditLogs(ctx context.Context, tenantID string, limit, offset int) ([]AuditEntry, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,actor_id::text,action,target_type,target_id,details,created_at
		FROM audit_logs WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var entry AuditEntry
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

func (r *Repository) RecordLogin(ctx context.Context, tenantID, userID string) error {
	return r.audit(ctx, tenantID, userID, "auth.login", "user", userID, nil)
}

func (r *Repository) audit(ctx context.Context, tenantID, actorID, action, targetType, targetID string, details map[string]any) error {
	return insertAudit(ctx, r.pool, tenantID, actorID, action, targetType, targetID, details)
}

type execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertAudit(ctx context.Context, e execer, tenantID, actorID, action, targetType, targetID string, details map[string]any) error {
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

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func normalizeError(err error) error {
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
