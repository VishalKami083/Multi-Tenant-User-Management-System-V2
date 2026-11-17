package tenant

import (
	"context"
	"strings"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"golang.org/x/crypto/bcrypt"
)

type Repository interface {
	CreateTenant(context.Context, string, string, string, string, string) (repoData.Tenant, repoData.User, error)
	GetTenant(context.Context, string) (repoData.Tenant, error)
	UpdateTenant(context.Context, string, string, string, string, string) (repoData.Tenant, error)
}

type Service struct {
	repo Repository
}

type Input struct {
	Name      string `json:"name"`
	Code      string `json:"code"`
	OwnerName string `json:"owner_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type Update struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Status string `json:"status"`
}

func New(repo Repository) *Service { return &Service{repo: repo} }

func (s *Service) Create(ctx context.Context, in Input) (repoData.Tenant, repoData.User, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Code = strings.ToLower(strings.TrimSpace(in.Code))
	in.OwnerName = strings.TrimSpace(in.OwnerName)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Name) < 2 || len(in.Name) > 160 || len(in.OwnerName) < 1 || len(in.OwnerName) > 160 {
		return repoData.Tenant{}, repoData.User{}, shared.Invalid("name must be between 2 and 160 characters and owner_name between 1 and 160")
	}
	if len(in.Code) < 2 || len(in.Code) > 63 || !shared.ValidCode(in.Code) {
		return repoData.Tenant{}, repoData.User{}, shared.Invalid("code must contain lowercase letters, digits, or hyphens and start with a letter or digit")
	}
	if !shared.ValidEmail(in.Email) || len(in.Password) < 12 || len(in.Password) > 72 {
		return repoData.Tenant{}, repoData.User{}, shared.Invalid("provide a valid email and a password between 12 and 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return repoData.Tenant{}, repoData.User{}, err
	}
	tenant, owner, err := s.repo.CreateTenant(ctx, in.Name, in.Code, in.OwnerName, in.Email, string(hash))
	return tenant, owner, shared.Translate(err)
}

func (s *Service) Get(ctx context.Context, identity shared.Identity) (repoData.Tenant, error) {
	tenant, err := s.repo.GetTenant(ctx, identity.TenantID)
	return tenant, shared.Translate(err)
}

func (s *Service) Update(ctx context.Context, identity shared.Identity, in Update) (repoData.Tenant, error) {
	current, err := s.repo.GetTenant(ctx, identity.TenantID)
	if err != nil {
		return repoData.Tenant{}, shared.Translate(err)
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
		return repoData.Tenant{}, shared.Invalid("tenant name must be between 2 and 160 characters")
	}
	if len(current.Code) < 2 || len(current.Code) > 63 || !shared.ValidCode(current.Code) {
		return repoData.Tenant{}, shared.Invalid("code must contain lowercase letters, digits, or hyphens and start with a letter or digit")
	}
	if current.Status != "active" && current.Status != "suspended" {
		return repoData.Tenant{}, shared.Invalid("status must be active or suspended")
	}
	tenant, err := s.repo.UpdateTenant(ctx, identity.TenantID, identity.UserID, current.Name, current.Code, current.Status)
	return tenant, shared.Translate(err)
}
