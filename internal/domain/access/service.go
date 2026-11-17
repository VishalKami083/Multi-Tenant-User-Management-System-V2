package access

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type Repository interface {
	Permissions(context.Context, string, string) ([]string, error)
	TenantActive(context.Context, string) (bool, error)
	ListRoles(context.Context, string) ([]repoData.Role, error)
	ListPermissions(context.Context) ([]repoData.Permission, error)
	CreateRole(context.Context, string, string, string, string) (repoData.Role, error)
	AssignRole(context.Context, string, string, string, string) error
	RemoveRole(context.Context, string, string, string, string) error
	SetRolePermissions(context.Context, string, string, string, []string) error
}

type Service struct {
	repo       Repository
	cacheTTL   time.Duration
	cacheMu    sync.RWMutex
	permission map[string]permissionEntry
	generation uint64
}

type permissionEntry struct {
	permissions map[string]struct{}
	expires     time.Time
}

type RoleInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

const maxPermissionEntries = 10000

func New(repo Repository, cacheTTL time.Duration) *Service {
	return &Service{repo: repo, cacheTTL: cacheTTL, permission: make(map[string]permissionEntry)}
}

func (s *Service) RequirePermission(ctx context.Context, identity shared.Identity, permission string) error {
	if permission != "tenant:update" {
		active, err := s.repo.TenantActive(ctx, identity.TenantID)
		if err != nil {
			return shared.Translate(err)
		}
		if !active {
			return shared.Forbidden()
		}
	}
	key := identity.TenantID + ":" + identity.UserID
	for attempts := 0; attempts < 3; attempts++ {
		now := time.Now()
		s.cacheMu.RLock()
		entry, ok := s.permission[key]
		generation := s.generation
		s.cacheMu.RUnlock()
		if ok && entry.expires.After(now) {
			return requireCachedPermission(entry, permission)
		}

		permissions, err := s.repo.Permissions(ctx, identity.TenantID, identity.UserID)
		if err != nil {
			return err
		}
		entry = newPermissionEntry(permissions, now.Add(s.cacheTTL))
		s.cacheMu.Lock()
		if generation != s.generation {
			s.cacheMu.Unlock()
			continue
		}
		s.evictExpiredEntries(now)
		s.permission[key] = entry
		s.cacheMu.Unlock()
		return requireCachedPermission(entry, permission)
	}

	permissions, err := s.repo.Permissions(ctx, identity.TenantID, identity.UserID)
	if err != nil {
		return err
	}
	return requireCachedPermission(newPermissionEntry(permissions, time.Time{}), permission)
}

func (s *Service) Invalidate(identity shared.Identity) {
	s.cacheMu.Lock()
	s.generation++
	delete(s.permission, identity.TenantID+":"+identity.UserID)
	s.cacheMu.Unlock()
}

func (s *Service) InvalidateTenant(tenantID string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.generation++
	for key := range s.permission {
		if strings.HasPrefix(key, tenantID+":") {
			delete(s.permission, key)
		}
	}
}

func (s *Service) InvalidateAll() {
	s.cacheMu.Lock()
	s.generation++
	clear(s.permission)
	s.cacheMu.Unlock()
}

func (s *Service) evictExpiredEntries(now time.Time) {
	if len(s.permission) < maxPermissionEntries {
		return
	}
	for cacheKey, cached := range s.permission {
		if !cached.expires.After(now) {
			delete(s.permission, cacheKey)
		}
	}
	if len(s.permission) >= maxPermissionEntries {
		s.permission = make(map[string]permissionEntry)
	}
}

func newPermissionEntry(permissions []string, expires time.Time) permissionEntry {
	set := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		set[permission] = struct{}{}
	}
	return permissionEntry{permissions: set, expires: expires}
}

func requireCachedPermission(entry permissionEntry, permission string) error {
	if _, ok := entry.permissions[permission]; !ok {
		return shared.Forbidden()
	}
	return nil
}

func (s *Service) ListRoles(ctx context.Context, identity shared.Identity) ([]repoData.Role, error) {
	return s.repo.ListRoles(ctx, identity.TenantID)
}

func (s *Service) ListPermissions(ctx context.Context) ([]repoData.Permission, error) {
	return s.repo.ListPermissions(ctx)
}

func (s *Service) CreateRole(ctx context.Context, identity shared.Identity, in RoleInput) (repoData.Role, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if len(in.Name) < 2 || len(in.Name) > 80 || len(in.Description) > 500 {
		return repoData.Role{}, shared.Invalid("role name must be 2-80 characters and description at most 500 characters")
	}
	role, err := s.repo.CreateRole(ctx, identity.TenantID, identity.UserID, in.Name, in.Description)
	return role, shared.Translate(err)
}

func (s *Service) AssignRole(ctx context.Context, identity shared.Identity, userID, roleID string) error {
	return shared.Translate(s.repo.AssignRole(ctx, identity.TenantID, identity.UserID, userID, roleID))
}

func (s *Service) RemoveRole(ctx context.Context, identity shared.Identity, userID, roleID string) error {
	return shared.Translate(s.repo.RemoveRole(ctx, identity.TenantID, identity.UserID, userID, roleID))
}

func (s *Service) SetRolePermissions(ctx context.Context, identity shared.Identity, roleID string, names []string) error {
	if len(names) > 100 {
		return shared.Invalid("at most 100 permissions may be assigned")
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if !shared.ValidPermission(name) {
			return shared.Invalid("permission names must use resource:action format")
		}
		if _, exists := seen[name]; exists {
			return shared.Invalid("permission names must be unique")
		}
		seen[name] = struct{}{}
	}
	return shared.Translate(s.repo.SetRolePermissions(ctx, identity.TenantID, identity.UserID, roleID, names))
}
