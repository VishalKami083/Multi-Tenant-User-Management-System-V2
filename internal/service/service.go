package service

import (
	"context"
	"time"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/access"
	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/audit"
	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/auth"
	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/membership"
	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/tenant"
	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/user"
	"github.com/vishalKami083/multitenant-usermgmt/internal/repository"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
)

type Identity = shared.Identity
type TenantInput = tenant.Input
type TenantUpdate = tenant.Update
type UserInput = user.Input
type UserPage = user.Page
type MembershipUpdate = membership.Update
type RoleInput = access.RoleInput
type Error = shared.Error

type Service struct {
	tenants     *tenant.Service
	auth        *auth.Service
	users       *user.Service
	memberships *membership.Service
	access      *access.Service
	audit       *audit.Service
}

func New(repo *repository.Repository, tokens *security.TokenManager, cacheTTL time.Duration) *Service {
	return &Service{
		tenants:     tenant.New(repo),
		auth:        auth.New(repo, tokens),
		users:       user.New(repo),
		memberships: membership.New(repo),
		access:      access.New(repo, cacheTTL),
		audit:       audit.New(repo),
	}
}

func (s *Service) CreateTenant(ctx context.Context, in TenantInput) (repoData.Tenant, repoData.User, error) {
	return s.tenants.Create(ctx, in)
}

func (s *Service) GetTenant(ctx context.Context, identity Identity) (repoData.Tenant, error) {
	return s.tenants.Get(ctx, identity)
}

func (s *Service) UpdateTenant(ctx context.Context, identity Identity, in TenantUpdate) (repoData.Tenant, error) {
	tenant, err := s.tenants.Update(ctx, identity, in)
	if err == nil {
		s.access.InvalidateTenant(identity.TenantID)
	}
	return tenant, err
}

func (s *Service) Login(ctx context.Context, tenantCode, email, password string) (security.TokenPair, error) {
	return s.auth.Login(ctx, tenantCode, email, password)
}

func (s *Service) Refresh(ctx context.Context, token string) (security.TokenPair, error) {
	return s.auth.Refresh(ctx, token)
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.auth.Logout(ctx, token)
}

func (s *Service) Authenticate(token string) (Identity, error) {
	return s.auth.Authenticate(token)
}

func (s *Service) RequirePermission(ctx context.Context, identity Identity, name string) error {
	return s.access.RequirePermission(ctx, identity, name)
}

func (s *Service) InvalidatePermissionCache(tenantID, userID string) {
	switch {
	case tenantID == "":
		s.access.InvalidateAll()
	case userID == "":
		s.access.InvalidateTenant(tenantID)
	default:
		s.access.Invalidate(Identity{TenantID: tenantID, UserID: userID})
	}
}

func (s *Service) ListUsers(ctx context.Context, identity Identity, search string, limit, offset int) (UserPage, error) {
	return s.users.List(ctx, identity, search, limit, offset)
}

func (s *Service) GetUser(ctx context.Context, identity Identity, id string) (repoData.User, error) {
	return s.users.Get(ctx, identity, id)
}

func (s *Service) CreateUser(ctx context.Context, identity Identity, in UserInput) (repoData.User, error) {
	return s.users.Create(ctx, identity, in)
}

func (s *Service) UpdateUser(ctx context.Context, identity Identity, id, name string) (repoData.User, error) {
	return s.users.Update(ctx, identity, id, name)
}

func (s *Service) DeleteUser(ctx context.Context, identity Identity, id string) error {
	err := s.users.Delete(ctx, identity, id)
	s.access.Invalidate(Identity{TenantID: identity.TenantID, UserID: id})
	return err
}

func (s *Service) AddMembership(ctx context.Context, identity Identity, userID string) error {
	err := s.memberships.Add(ctx, identity, userID)
	s.access.Invalidate(Identity{TenantID: identity.TenantID, UserID: userID})
	return err
}

func (s *Service) UpdateMembership(ctx context.Context, identity Identity, userID string, in MembershipUpdate) error {
	err := s.memberships.Update(ctx, identity, userID, in)
	if err == nil {
		s.access.Invalidate(Identity{TenantID: identity.TenantID, UserID: userID})
	}
	return err
}

func (s *Service) ListRoles(ctx context.Context, identity Identity) ([]repoData.Role, error) {
	return s.access.ListRoles(ctx, identity)
}

func (s *Service) ListPermissions(ctx context.Context) ([]repoData.Permission, error) {
	return s.access.ListPermissions(ctx)
}

func (s *Service) CreateRole(ctx context.Context, identity Identity, in RoleInput) (repoData.Role, error) {
	return s.access.CreateRole(ctx, identity, in)
}

func (s *Service) AssignRole(ctx context.Context, identity Identity, userID, roleID string) error {
	err := s.access.AssignRole(ctx, identity, userID, roleID)
	s.access.Invalidate(Identity{TenantID: identity.TenantID, UserID: userID})
	return err
}

func (s *Service) RemoveRole(ctx context.Context, identity Identity, userID, roleID string) error {
	err := s.access.RemoveRole(ctx, identity, userID, roleID)
	s.access.Invalidate(Identity{TenantID: identity.TenantID, UserID: userID})
	return err
}

func (s *Service) SetRolePermissions(ctx context.Context, identity Identity, roleID string, names []string) error {
	err := s.access.SetRolePermissions(ctx, identity, roleID, names)
	if err == nil {
		s.access.InvalidateTenant(identity.TenantID)
	}
	return err
}

func (s *Service) AuditLogs(ctx context.Context, identity Identity, limit, offset int) ([]repoData.AuditEntry, error) {
	return s.audit.List(ctx, identity, limit, offset)
}
