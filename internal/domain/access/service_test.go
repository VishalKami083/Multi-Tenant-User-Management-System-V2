package access

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type fakeRepository struct {
	permissions map[string][]string
}

type blockingRepository struct {
	*fakeRepository
	firstFetchStarted chan struct{}
	releaseFirstFetch chan struct{}
	calls             int
}

func (r *fakeRepository) Permissions(_ context.Context, tenantID, userID string) ([]string, error) {
	return append([]string(nil), r.permissions[tenantID+":"+userID]...), nil
}

func (r *blockingRepository) Permissions(_ context.Context, tenantID, userID string) ([]string, error) {
	permissions := append([]string(nil), r.permissions[tenantID+":"+userID]...)
	r.calls++
	if r.calls == 1 {
		close(r.firstFetchStarted)
		<-r.releaseFirstFetch
	}
	return permissions, nil
}

func (*fakeRepository) TenantActive(context.Context, string) (bool, error) { return true, nil }
func (*fakeRepository) ListRoles(context.Context, string) ([]repoData.Role, error) {
	return nil, nil
}
func (*fakeRepository) ListPermissions(context.Context) ([]repoData.Permission, error) {
	return nil, nil
}
func (*fakeRepository) CreateRole(context.Context, string, string, string, string) (repoData.Role, error) {
	return repoData.Role{}, nil
}
func (*fakeRepository) AssignRole(context.Context, string, string, string, string) error { return nil }
func (*fakeRepository) RemoveRole(context.Context, string, string, string, string) error { return nil }
func (*fakeRepository) SetRolePermissions(context.Context, string, string, string, []string) error {
	return nil
}

func TestPermissionCacheInvalidationIsScoped(t *testing.T) {
	repo := &fakeRepository{permissions: map[string][]string{
		"tenant:user-a":       {"user:read"},
		"tenant:user-b":       {"user:read"},
		"tenant-extra:user-c": {"user:read"},
	}}
	service := New(repo, time.Hour)
	ctx := context.Background()
	identities := []shared.Identity{
		{TenantID: "tenant", UserID: "user-a"},
		{TenantID: "tenant", UserID: "user-b"},
		{TenantID: "tenant-extra", UserID: "user-c"},
	}
	for _, identity := range identities {
		if err := service.RequirePermission(ctx, identity, "user:read"); err != nil {
			t.Fatalf("initial permission for %s: %v", identity.UserID, err)
		}
	}

	repo.permissions["tenant:user-a"] = nil
	service.Invalidate(identities[0])
	if err := service.RequirePermission(ctx, identities[0], "user:read"); err == nil {
		t.Fatal("individual invalidation retained a revoked permission")
	}
	if err := service.RequirePermission(ctx, identities[1], "user:read"); err != nil {
		t.Fatalf("individual invalidation affected another member: %v", err)
	}

	repo.permissions["tenant:user-b"] = nil
	repo.permissions["tenant-extra:user-c"] = nil
	service.InvalidateTenant("tenant")
	for _, identity := range identities[:2] {
		if err := service.RequirePermission(ctx, identity, "user:read"); err == nil {
			t.Errorf("tenant-wide invalidation retained permission for %s", identity.UserID)
		}
	}
	if err := service.RequirePermission(ctx, identities[2], "user:read"); err != nil {
		t.Fatalf("tenant-wide invalidation crossed tenant boundary: %v", err)
	}
}

func TestPermissionCacheEvictsEntriesAtCapacity(t *testing.T) {
	repo := &fakeRepository{permissions: map[string][]string{}}
	service := New(repo, time.Hour)
	service.permission["expired:user"] = permissionEntry{
		permissions: map[string]struct{}{"user:read": {}},
		expires:     time.Now().Add(-time.Minute),
	}
	for index := 0; index < maxPermissionEntries; index++ {
		key := fmt.Sprintf("tenant-%d:user", index)
		service.permission[key] = permissionEntry{
			permissions: map[string]struct{}{"user:read": {}},
			expires:     time.Now().Add(time.Hour),
		}
	}
	repo.permissions["new-tenant:new-user"] = []string{"user:read"}

	if err := service.RequirePermission(context.Background(), shared.Identity{
		TenantID: "new-tenant", UserID: "new-user",
	}, "user:read"); err != nil {
		t.Fatalf("permission lookup at capacity: %v", err)
	}
	if _, exists := service.permission["expired:user"]; exists {
		t.Fatal("expired cache entry was not evicted")
	}
	if len(service.permission) > maxPermissionEntries {
		t.Fatalf("cache entries = %d, limit = %d", len(service.permission), maxPermissionEntries)
	}
}

func TestInvalidationPreventsStaleInFlightCacheFill(t *testing.T) {
	identity := shared.Identity{TenantID: "tenant", UserID: "user"}
	repo := &blockingRepository{
		fakeRepository: &fakeRepository{permissions: map[string][]string{
			"tenant:user": {"user:read"},
		}},
		firstFetchStarted: make(chan struct{}),
		releaseFirstFetch: make(chan struct{}),
	}
	service := New(repo, time.Hour)
	result := make(chan error, 1)
	go func() {
		result <- service.RequirePermission(context.Background(), identity, "user:read")
	}()

	<-repo.firstFetchStarted
	repo.permissions["tenant:user"] = nil
	service.Invalidate(identity)
	close(repo.releaseFirstFetch)

	if err := <-result; err == nil {
		t.Fatal("an in-flight stale lookup allowed a permission after invalidation")
	}
	if repo.calls != 2 {
		t.Fatalf("permission queries = %d, want stale result discarded and refetched", repo.calls)
	}
}
