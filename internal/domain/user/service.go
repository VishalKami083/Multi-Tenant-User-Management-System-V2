package user

import (
	"context"
	"strings"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"golang.org/x/crypto/bcrypt"
)

type Repository interface {
	ListUsers(context.Context, string, string, int, int) ([]repoData.User, int, error)
	GetUser(context.Context, string, string) (repoData.User, error)
	CreateUser(context.Context, string, string, string, string, string) (repoData.User, error)
	UpdateUser(context.Context, string, string, string, string) (repoData.User, error)
	DeleteUser(context.Context, string, string, string) error
}

type Service struct{ repo Repository }

type Input struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Page struct {
	Items  []repoData.User `json:"items"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
	Total  int             `json:"total"`
}

func New(repo Repository) *Service { return &Service{repo: repo} }

func (s *Service) List(ctx context.Context, identity shared.Identity, search string, limit, offset int) (Page, error) {
	if limit < 1 || limit > 100 || offset < 0 {
		return Page{}, shared.Invalid("limit must be 1-100 and offset must be non-negative")
	}
	items, total, err := s.repo.ListUsers(ctx, identity.TenantID, search, limit, offset)
	return Page{Items: items, Limit: limit, Offset: offset, Total: total}, err
}

func (s *Service) Get(ctx context.Context, identity shared.Identity, id string) (repoData.User, error) {
	user, err := s.repo.GetUser(ctx, identity.TenantID, id)
	return user, shared.Translate(err)
}

func (s *Service) Create(ctx context.Context, identity shared.Identity, in Input) (repoData.User, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Name) < 1 || len(in.Name) > 160 || !shared.ValidEmail(in.Email) || len(in.Password) < 12 || len(in.Password) > 72 {
		return repoData.User{}, shared.Invalid("name must be 1-160 characters, email valid, and password 12-72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return repoData.User{}, err
	}
	user, err := s.repo.CreateUser(ctx, identity.TenantID, identity.UserID, in.Name, in.Email, string(hash))
	return user, shared.Translate(err)
}

func (s *Service) Update(ctx context.Context, identity shared.Identity, id, name string) (repoData.User, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 160 {
		return repoData.User{}, shared.Invalid("name must be between 1 and 160 characters")
	}
	user, err := s.repo.UpdateUser(ctx, identity.TenantID, identity.UserID, id, name)
	return user, shared.Translate(err)
}

func (s *Service) Delete(ctx context.Context, identity shared.Identity, id string) error {
	return shared.Translate(s.repo.DeleteUser(ctx, identity.TenantID, identity.UserID, id))
}
