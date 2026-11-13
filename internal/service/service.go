package service

import (
	"context"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/vishalKami083/multitenant-usermgmt/internal/repository"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
	"golang.org/x/crypto/bcrypt"
)

type Identity struct {
	TenantID string
	UserID   string
}

type TenantInput struct {
	Name      string `json:"name"`
	Code      string `json:"code"`
	OwnerName string `json:"owner_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type UserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RoleInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type TenantUpdate struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Status string `json:"status"`
}

type UserPage struct {
	Items  []repository.User `json:"items"`
	Limit  int               `json:"limit"`
	Offset int               `json:"offset"`
	Total  int               `json:"total"`
}

type permissionEntry struct {
	permissions map[string]struct{}
	expires     time.Time
}

type Service struct {
	repo       *repository.Repository
	tokens     *security.TokenManager
	cacheTTL   time.Duration
	cacheMu    sync.RWMutex
	permission map[string]permissionEntry
}

const maxPermissionEntries = 10000

func New(repo *repository.Repository, tokens *security.TokenManager, cacheTTL time.Duration) *Service {
	return &Service{repo: repo, tokens: tokens, cacheTTL: cacheTTL, permission: make(map[string]permissionEntry)}
}

func (s *Service) CreateTenant(ctx context.Context, in TenantInput) (repository.Tenant, repository.User, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Code = strings.ToLower(strings.TrimSpace(in.Code))
	in.OwnerName = strings.TrimSpace(in.OwnerName)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Name) < 2 || len(in.Name) > 160 || len(in.OwnerName) < 1 || len(in.OwnerName) > 160 {
		return repository.Tenant{}, repository.User{}, invalid("name must be between 2 and 160 characters and owner_name between 1 and 160")
	}
	if len(in.Code) < 2 || len(in.Code) > 63 || !validCode(in.Code) {
		return repository.Tenant{}, repository.User{}, invalid("code must contain lowercase letters, digits, or hyphens and start with a letter or digit")
	}
	if !validEmail(in.Email) || len(in.Password) < 12 || len(in.Password) > 72 {
		return repository.Tenant{}, repository.User{}, invalid("provide a valid email and a password between 12 and 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return repository.Tenant{}, repository.User{}, err
	}
	tenant, owner, err := s.repo.CreateTenant(ctx, in.Name, in.Code, in.OwnerName, in.Email, string(hash))
	return tenant, owner, translate(err)
}

func (s *Service) Login(ctx context.Context, tenantCode, email, password string) (security.TokenPair, error) {
	rec, err := s.repo.FindLogin(ctx, strings.ToLower(strings.TrimSpace(tenantCode)), strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return security.TokenPair{}, unauthorized()
	}
	if rec.TenantStatus != "active" || rec.MembershipStatus != "active" ||
		bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)) != nil {
		return security.TokenPair{}, unauthorized()
	}
	now := time.Now().UTC()
	pair, hash, err := s.tokens.Issue(rec.TenantID, rec.UserID, now)
	if err != nil {
		return security.TokenPair{}, err
	}
	if err := s.repo.StoreRefresh(ctx, hash, rec.TenantID, rec.UserID, pair.RefreshExpiresAt); err != nil {
		return security.TokenPair{}, err
	}
	if err := s.repo.RecordLogin(ctx, rec.TenantID, rec.UserID); err != nil {
		return security.TokenPair{}, err
	}
	return pair, nil
}

func (s *Service) Refresh(ctx context.Context, raw string) (security.TokenPair, error) {
	if len(raw) < 40 || len(raw) > 128 {
		return security.TokenPair{}, unauthorized()
	}
	now := time.Now().UTC()
	oldHash := security.HashRefresh(raw)
	identity, err := s.repo.RefreshIdentity(ctx, oldHash, now)
	if err != nil {
		return security.TokenPair{}, unauthorized()
	}
	pair, newHash, err := s.tokens.Issue(identity.TenantID, identity.UserID, now)
	if err != nil {
		return security.TokenPair{}, err
	}
	if _, err := s.repo.RotateRefresh(ctx, oldHash, newHash, now, pair.RefreshExpiresAt); err != nil {
		return security.TokenPair{}, unauthorized()
	}
	return pair, nil
}

func (s *Service) Logout(ctx context.Context, raw string) error {
	if len(raw) < 40 || len(raw) > 128 {
		return unauthorized()
	}
	return s.repo.RevokeRefresh(ctx, security.HashRefresh(raw), time.Now().UTC())
}

func (s *Service) Authenticate(token string) (Identity, error) {
	claims, err := s.tokens.Parse(token)
	if err != nil {
		return Identity{}, unauthorized()
	}
	return Identity{TenantID: claims.TenantID, UserID: claims.UserID}, nil
}

func (s *Service) RequirePermission(ctx context.Context, identity Identity, permission string) error {
	if permission != "tenant:update" {
		active, err := s.repo.TenantActive(ctx, identity.TenantID)
		if err != nil {
			return translate(err)
		}
		if !active {
			return forbidden()
		}
	}
	key := identity.TenantID + ":" + identity.UserID
	now := time.Now()
	s.cacheMu.RLock()
	entry, ok := s.permission[key]
	s.cacheMu.RUnlock()
	if !ok || !entry.expires.After(now) {
		permissions, err := s.repo.Permissions(ctx, identity.TenantID, identity.UserID)
		if err != nil {
			return err
		}
		set := make(map[string]struct{}, len(permissions))
		for _, p := range permissions {
			set[p] = struct{}{}
		}
		entry = permissionEntry{permissions: set, expires: now.Add(s.cacheTTL)}
		s.cacheMu.Lock()
		if len(s.permission) >= maxPermissionEntries {
			for cacheKey, cached := range s.permission {
				if !cached.expires.After(now) {
					delete(s.permission, cacheKey)
				}
			}
			if len(s.permission) >= maxPermissionEntries {
				s.permission = make(map[string]permissionEntry)
			}
		}
		s.permission[key] = entry
		s.cacheMu.Unlock()
	}
	if _, ok := entry.permissions[permission]; !ok {
		return forbidden()
	}
	return nil
}

func (s *Service) GetTenant(ctx context.Context, identity Identity) (repository.Tenant, error) {
	tenant, err := s.repo.GetTenant(ctx, identity.TenantID)
	return tenant, translate(err)
}

func (s *Service) UpdateTenant(ctx context.Context, identity Identity, in TenantUpdate) (repository.Tenant, error) {
	current, err := s.repo.GetTenant(ctx, identity.TenantID)
	if err != nil {
		return repository.Tenant{}, translate(err)
	}
	if strings.TrimSpace(in.Name) != "" {
		current.Name = strings.TrimSpace(in.Name)
	}
	if strings.TrimSpace(in.Code) != "" {
		current.Code = strings.ToLower(strings.TrimSpace(in.Code))
	}
	if in.Status != "" {
		current.Status = strings.ToLower(strings.TrimSpace(in.Status))
	}
	if len(current.Name) < 2 || len(current.Name) > 160 {
		return repository.Tenant{}, invalid("tenant name must be between 2 and 160 characters")
	}
	if len(current.Code) < 2 || len(current.Code) > 63 || !validCode(current.Code) {
		return repository.Tenant{}, invalid("code must contain lowercase letters, digits, or hyphens and start with a letter or digit")
	}
	if current.Status != "active" && current.Status != "suspended" {
		return repository.Tenant{}, invalid("status must be active or suspended")
	}
	tenant, err := s.repo.UpdateTenant(ctx, identity.TenantID, identity.UserID, current.Name, current.Code, current.Status)
	if err == nil {
		s.invalidateTenant(identity.TenantID)
	}
	return tenant, translate(err)
}

func (s *Service) invalidate(tenantID, userID string) {
	s.cacheMu.Lock()
	delete(s.permission, tenantID+":"+userID)
	s.cacheMu.Unlock()
}

func (s *Service) ListUsers(ctx context.Context, identity Identity, search string, limit, offset int) (UserPage, error) {
	if limit < 1 || limit > 100 || offset < 0 {
		return UserPage{}, invalid("limit must be 1-100 and offset must be non-negative")
	}
	items, total, err := s.repo.ListUsers(ctx, identity.TenantID, search, limit, offset)
	return UserPage{Items: items, Limit: limit, Offset: offset, Total: total}, err
}

func (s *Service) GetUser(ctx context.Context, identity Identity, id string) (repository.User, error) {
	user, err := s.repo.GetUser(ctx, identity.TenantID, id)
	return user, translate(err)
}

func (s *Service) CreateUser(ctx context.Context, identity Identity, in UserInput) (repository.User, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Name) < 1 || len(in.Name) > 160 || !validEmail(in.Email) || len(in.Password) < 12 || len(in.Password) > 72 {
		return repository.User{}, invalid("name must be 1-160 characters, email valid, and password 12-72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return repository.User{}, err
	}
	user, err := s.repo.CreateUser(ctx, identity.TenantID, identity.UserID, in.Name, in.Email, string(hash))
	return user, translate(err)
}

func (s *Service) UpdateUser(ctx context.Context, identity Identity, id, name string) (repository.User, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 160 {
		return repository.User{}, invalid("name must be between 1 and 160 characters")
	}
	user, err := s.repo.UpdateUser(ctx, identity.TenantID, identity.UserID, id, name)
	return user, translate(err)
}

func (s *Service) DeleteUser(ctx context.Context, identity Identity, id string) error {
	err := s.repo.DeleteUser(ctx, identity.TenantID, identity.UserID, id)
	s.invalidate(identity.TenantID, id)
	return translate(err)
}

func (s *Service) ListRoles(ctx context.Context, identity Identity) ([]repository.Role, error) {
	return s.repo.ListRoles(ctx, identity.TenantID)
}

func (s *Service) ListPermissions(ctx context.Context) ([]repository.Permission, error) {
	return s.repo.ListPermissions(ctx)
}

func (s *Service) CreateRole(ctx context.Context, identity Identity, in RoleInput) (repository.Role, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if len(in.Name) < 2 || len(in.Name) > 80 || len(in.Description) > 500 {
		return repository.Role{}, invalid("role name must be 2-80 characters and description at most 500 characters")
	}
	role, err := s.repo.CreateRole(ctx, identity.TenantID, identity.UserID, in.Name, in.Description)
	return role, translate(err)
}

func (s *Service) AssignRole(ctx context.Context, identity Identity, userID, roleID string) error {
	err := s.repo.AssignRole(ctx, identity.TenantID, identity.UserID, userID, roleID)
	s.invalidate(identity.TenantID, userID)
	return translate(err)
}

func (s *Service) RemoveRole(ctx context.Context, identity Identity, userID, roleID string) error {
	err := s.repo.RemoveRole(ctx, identity.TenantID, identity.UserID, userID, roleID)
	s.invalidate(identity.TenantID, userID)
	return translate(err)
}

func (s *Service) AddMembership(ctx context.Context, identity Identity, userID string) error {
	err := s.repo.AddMembership(ctx, identity.TenantID, identity.UserID, userID)
	s.invalidate(identity.TenantID, userID)
	return translate(err)
}

func (s *Service) SetRolePermissions(ctx context.Context, identity Identity, roleID string, names []string) error {
	if len(names) > 100 {
		return invalid("at most 100 permissions may be assigned")
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if !validPermission(name) {
			return invalid("permission names must use resource:action format")
		}
		if _, exists := seen[name]; exists {
			return invalid("permission names must be unique")
		}
		seen[name] = struct{}{}
	}
	if err := s.repo.SetRolePermissions(ctx, identity.TenantID, identity.UserID, roleID, names); err != nil {
		return translate(err)
	}
	s.invalidateTenant(identity.TenantID)
	return nil
}

func (s *Service) AuditLogs(ctx context.Context, identity Identity, limit, offset int) ([]repository.AuditEntry, error) {
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, invalid("limit must be 1-100 and offset must be non-negative")
	}
	return s.repo.AuditLogs(ctx, identity.TenantID, limit, offset)
}

func (s *Service) invalidateTenant(tenantID string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for key := range s.permission {
		if strings.HasPrefix(key, tenantID+":") {
			delete(s.permission, key)
		}
	}
}

func validEmail(value string) bool {
	if len(value) > 254 {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && strings.Contains(value, "@")
}

func validCode(value string) bool {
	for i, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && !(r == '-' && i > 0) {
			return false
		}
	}
	return len(value) >= 2 && value[0] != '-'
}

func validPermission(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
				return false
			}
		}
	}
	return true
}
