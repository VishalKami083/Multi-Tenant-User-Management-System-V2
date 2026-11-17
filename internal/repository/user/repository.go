package userrepo

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vishalKami083/multitenant-usermgmt/internal/database"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type UserRepository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *UserRepository { return &UserRepository{pool: pool} }

func (r *UserRepository) ListUsers(ctx context.Context, tenantID, search string, limit, offset int) ([]repoData.User, int, error) {
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
	users := make([]repoData.User, 0)
	for rows.Next() {
		var user repoData.User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt); err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	return users, total, rows.Err()
}

func (r *UserRepository) GetUser(ctx context.Context, tenantID, userID string) (repoData.User, error) {
	var user repoData.User
	err := r.pool.QueryRow(ctx, `SELECT u.id::text,COALESCE(m.display_name,u.name),u.email,u.created_at FROM users u
		JOIN memberships m ON m.user_id=u.id WHERE m.tenant_id=$1 AND m.user_id=$2
		AND m.status='active' AND m.deleted_at IS NULL`,
		tenantID, userID).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoData.User{}, repoData.ErrNotFound
	}
	return user, err
}

func (r *UserRepository) CreateUser(ctx context.Context, tenantID, actorID, name, email, hash string) (repoData.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return repoData.User{}, err
	}
	defer tx.Rollback(ctx)
	var user repoData.User
	err = tx.QueryRow(ctx, `INSERT INTO users(name,email,password_hash) VALUES($1,lower($2),$3)
		RETURNING id::text,name,email,created_at`, name, email, hash).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if err != nil {
		return repoData.User{}, repoData.NormalizeError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(tenant_id,user_id,display_name) VALUES($1,$2,$3)`,
		tenantID, user.ID, name); err != nil {
		return repoData.User{}, repoData.NormalizeError(err)
	}
	if err = repoData.InsertAudit(ctx, tx, tenantID, actorID, "user.created", "user", user.ID, map[string]any{"email": user.Email}); err != nil {
		return repoData.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return repoData.User{}, err
	}
	return user, nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, tenantID, actorID, userID, name string) (repoData.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return repoData.User{}, err
	}
	defer tx.Rollback(ctx)
	var user repoData.User
	err = tx.QueryRow(ctx, `UPDATE memberships m SET display_name=$3 FROM users u
		WHERE m.tenant_id=$1 AND m.user_id=u.id AND m.user_id=$2 AND m.deleted_at IS NULL
		RETURNING u.id::text,m.display_name,u.email,u.created_at`, tenantID, userID, name).
		Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoData.User{}, repoData.ErrNotFound
	}
	if err != nil {
		return repoData.User{}, err
	}
	if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "user.updated", "user", userID, map[string]any{"name": name}); err != nil {
		return repoData.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return repoData.User{}, err
	}
	return user, nil
}

func (r *UserRepository) DeleteUser(ctx context.Context, tenantID, actorID, userID string) error {
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
		return repoData.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM membership_roles WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID); err != nil {
		return err
	}
	if err := repoData.InsertAudit(ctx, tx, tenantID, actorID, "user.deleted", "user", userID, nil); err != nil {
		return err
	}
	if err := database.NotifyPermissionCacheInvalidation(ctx, tx, tenantID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
