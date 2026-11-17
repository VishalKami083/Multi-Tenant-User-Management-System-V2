package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vishalKami083/multitenant-usermgmt/internal/config"
	"github.com/vishalKami083/multitenant-usermgmt/internal/database"
	"github.com/vishalKami083/multitenant-usermgmt/internal/repository"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticationRBACAndMembershipLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, config.Config{DatabaseURL: dsn, DBMaxConns: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	repo := repository.New(pool)
	password := "correct-horse-battery"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant, owner, err := repo.CreateTenant(ctx, "Service integration", "svc-"+suffix, "Owner", "svc-"+suffix+"@example.test", string(passwordHash))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupServiceIntegration(t, ctx, pool, tenant.ID, owner.ID)

	app := New(repo, security.NewTokenManager("integration-secret-at-least-32-bytes", time.Minute, time.Hour), time.Minute)
	if _, err := app.Login(ctx, tenant.Code, owner.Email, "wrong-password"); err == nil {
		t.Fatal("wrong password should be rejected")
	} else {
		var appErr *Error
		if !errors.As(err, &appErr) || appErr.Status != 401 {
			t.Fatalf("wrong-password error = %v, want 401", err)
		}
	}
	audit, err := repo.AuditLogs(ctx, tenant.ID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	failedLoginAudited := false
	for _, entry := range audit {
		if entry.Action == "auth.login_failed" {
			failedLoginAudited = entry.ActorID == nil && len(entry.Details) == 0
		}
	}
	if !failedLoginAudited {
		t.Fatal("failed login should be audited without actor or credential details")
	}

	tokens, err := app.Login(ctx, tenant.Code, owner.Email, password)
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{TenantID: tenant.ID, UserID: owner.ID}
	if err := app.RequirePermission(ctx, identity, "user:read"); err != nil {
		t.Fatalf("admin should initially have user:read: %v", err)
	}
	roles, err := repo.ListRoles(ctx, tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 {
		t.Fatalf("roles count = %d, want initial admin role", len(roles))
	}
	if err := app.SetRolePermissions(ctx, identity, roles[0].ID, []string{"tenant:read", "membership:update"}); err != nil {
		t.Fatal(err)
	}
	if err := app.RequirePermission(ctx, identity, "user:read"); err == nil {
		t.Fatal("revoked permission should be denied immediately using the same identity")
	}
	if err := app.RequirePermission(ctx, identity, "tenant:read"); err != nil {
		t.Fatalf("retained permission should remain available: %v", err)
	}

	member, err := repo.CreateUser(ctx, tenant.ID, owner.ID, "Member", "member-"+suffix+"@example.test", string(passwordHash))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupServiceIntegration(t, ctx, pool, tenant.ID, member.ID)
	if err := app.AssignRole(ctx, identity, member.ID, roles[0].ID); err != nil {
		t.Fatal(err)
	}
	memberIdentity := Identity{TenantID: tenant.ID, UserID: member.ID}
	if err := app.RequirePermission(ctx, memberIdentity, "tenant:read"); err != nil {
		t.Fatalf("assigned member should initially have tenant:read: %v", err)
	}
	if err := app.UpdateMembership(ctx, identity, member.ID, MembershipUpdate{Status: "suspended"}); err != nil {
		t.Fatal(err)
	}
	if err := app.RequirePermission(ctx, memberIdentity, "tenant:read"); err == nil {
		t.Fatal("suspended membership should immediately lose permissions")
	}
	if err := app.UpdateMembership(ctx, identity, member.ID, MembershipUpdate{Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := app.RequirePermission(ctx, memberIdentity, "tenant:read"); err != nil {
		t.Fatalf("reactivated membership should regain retained permissions: %v", err)
	}

	rotated, err := app.Refresh(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshToken == tokens.RefreshToken {
		t.Fatal("refresh rotation should issue a new refresh token")
	}
	if _, err := app.Refresh(ctx, tokens.RefreshToken); err == nil {
		t.Fatal("a rotated refresh token must not be reusable")
	}
}

func TestPermissionCacheInvalidationAcrossInstances(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, config.Config{DatabaseURL: dsn, DBMaxConns: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	repo := repository.New(pool)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant, owner, err := repo.CreateTenant(ctx, "Cache broadcast", "cache-"+suffix, "Owner", "cache-"+suffix+"@example.test", "test-hash")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupServiceIntegration(t, ctx, pool, tenant.ID, owner.ID)

	tokens := security.NewTokenManager("integration-secret-at-least-32-bytes", time.Minute, time.Hour)
	firstInstance := New(repo, tokens, time.Minute)
	secondInstance := New(repo, tokens, time.Minute)
	identity := Identity{TenantID: tenant.ID, UserID: owner.ID}
	if err := firstInstance.RequirePermission(ctx, identity, "user:read"); err != nil {
		t.Fatalf("initial permission lookup: %v", err)
	}

	listenerCtx, stopListener := context.WithCancel(ctx)
	ready := make(chan struct{})
	listenerDone := make(chan error, 1)
	var readyOnce sync.Once
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		listenerDone <- database.ListenPermissionCacheInvalidations(listenerCtx, dsn, logger, func(tenantID, userID string) {
			if tenantID == "" {
				readyOnce.Do(func() { close(ready) })
				return
			}
			firstInstance.InvalidatePermissionCache(tenantID, userID)
		})
	}()
	defer func() {
		stopListener()
		select {
		case err := <-listenerDone:
			if err != nil {
				t.Errorf("permission cache listener: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("permission cache listener did not stop after cancellation")
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatalf("permission cache listener did not become ready: %v", ctx.Err())
	}

	roles, err := repo.ListRoles(ctx, tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 {
		t.Fatalf("admin role count = %d, want 1", len(roles))
	}
	if err := secondInstance.SetRolePermissions(ctx, identity, roles[0].ID, []string{"tenant:read"}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		err := firstInstance.RequirePermission(ctx, identity, "user:read")
		if err != nil {
			var appErr *Error
			if !errors.As(err, &appErr) || appErr.Status != 403 {
				t.Fatalf("permission after remote revocation = %v, want 403", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first instance retained a revoked permission after the database notification")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func cleanupServiceIntegration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string, userIDs ...string) {
	t.Helper()
	for _, query := range []string{
		`DELETE FROM audit_logs WHERE tenant_id=$1`,
		`DELETE FROM refresh_tokens WHERE tenant_id=$1`,
		`DELETE FROM memberships WHERE tenant_id=$1`,
		`DELETE FROM roles WHERE tenant_id=$1`,
	} {
		if _, err := pool.Exec(ctx, query, tenantID); err != nil {
			t.Errorf("clean integration records: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID); err != nil {
		t.Errorf("clean integration tenant: %v", err)
	}
	for _, userID := range userIDs {
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID); err != nil {
			t.Errorf("clean integration user: %v", err)
		}
	}
}
