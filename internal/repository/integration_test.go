package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vishalKami083/multitenant-usermgmt/internal/config"
	"github.com/vishalKami083/multitenant-usermgmt/internal/database"
)

func TestTenantIsolationAndMultiTenantMembership(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, config.Config{DatabaseURL: dsn, DBMaxConns: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	repo := New(pool)
	suffix := randomSuffix(t)
	tenantA, ownerA, err := repo.CreateTenant(ctx, "Integration A", "it-a-"+suffix, "Owner A", "a-"+suffix+"@example.test", "bcrypt-hash")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, ownerB, err := repo.CreateTenant(ctx, "Integration B", "it-b-"+suffix, "Owner B", "b-"+suffix+"@example.test", "bcrypt-hash")
	if err != nil {
		cleanupIntegrationData(t, ctx, pool, tenantA.ID, ownerA.ID)
		t.Fatal(err)
	}
	defer cleanupIntegrationData(t, ctx, pool, tenantA.ID, ownerA.ID, tenantB.ID, ownerB.ID)

	if _, err := repo.GetUser(ctx, tenantA.ID, ownerB.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant user lookup should return not found, got %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE memberships SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`,
		tenantA.ID, ownerA.ID); err != nil {
		t.Fatal(err)
	}
	users, total, err := repo.ListUsers(ctx, tenantA.ID, "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(users) != 0 {
		t.Fatalf("suspended membership should not be listed: total=%d users=%+v", total, users)
	}
	if _, err := repo.GetUser(ctx, tenantA.ID, ownerA.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("suspended membership detail should return not found, got %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE memberships SET status='active' WHERE tenant_id=$1 AND user_id=$2`,
		tenantA.ID, ownerA.ID); err != nil {
		t.Fatal(err)
	}
	users, total, err = repo.ListUsers(ctx, tenantA.ID, "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(users) != 1 || users[0].ID != ownerA.ID {
		t.Fatalf("tenant A list leaked or lost data: total=%d users=%+v", total, users)
	}
	if err := repo.AddMembership(ctx, tenantB.ID, ownerB.ID, ownerA.ID); err != nil {
		t.Fatal(err)
	}
	users, total, err = repo.ListUsers(ctx, tenantB.ID, "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(users) != 2 {
		t.Fatalf("user should be linkable to multiple tenants; got total=%d users=%d", total, len(users))
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func cleanupIntegrationData(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantIDs ...string) {
	t.Helper()
	for i := 0; i < len(tenantIDs); i += 2 {
		tenantID := tenantIDs[i]
		queries := []struct {
			query string
			args  []any
		}{
			{`DELETE FROM audit_logs WHERE tenant_id=$1`, []any{tenantID}},
			{`DELETE FROM refresh_tokens WHERE tenant_id=$1`, []any{tenantID}},
			{`DELETE FROM memberships WHERE tenant_id=$1`, []any{tenantID}},
			{`DELETE FROM roles WHERE tenant_id=$1`, []any{tenantID}},
		}
		for _, item := range queries {
			if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
				t.Errorf("clean integration records: %v", err)
			}
		}
	}
	for i := 1; i < len(tenantIDs); i += 2 {
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, tenantIDs[i]); err != nil {
			t.Errorf("clean integration users: %v", err)
		}
	}
	for i := 0; i < len(tenantIDs); i += 2 {
		if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantIDs[i]); err != nil {
			t.Errorf("clean integration tenants: %v", err)
		}
	}
}
