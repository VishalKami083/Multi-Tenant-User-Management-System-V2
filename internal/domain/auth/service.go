package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
	"golang.org/x/crypto/bcrypt"
)

type Repository interface {
	FindLogin(context.Context, string, string) (repoData.LoginRecord, error)
	StoreRefresh(context.Context, []byte, string, string, time.Time) error
	RefreshIdentity(context.Context, []byte, time.Time) (repoData.RefreshedIdentity, error)
	RotateRefresh(context.Context, []byte, []byte, time.Time, time.Time) (repoData.RefreshedIdentity, error)
	RevokeRefresh(context.Context, []byte, time.Time) error
	RecordLogin(context.Context, string, string) error
	RecordFailedLogin(context.Context, string) error
}

type Service struct {
	repo   Repository
	tokens *security.TokenManager
}

func New(repo Repository, tokens *security.TokenManager) *Service {
	return &Service{repo: repo, tokens: tokens}
}

func (s *Service) Login(ctx context.Context, tenantCode, email, password string) (security.TokenPair, error) {
	tenantCode = strings.ToLower(strings.TrimSpace(tenantCode))
	rec, err := s.repo.FindLogin(ctx, tenantCode, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		if !errors.Is(err, repoData.ErrNotFound) {
			return security.TokenPair{}, err
		}
		return security.TokenPair{}, s.rejectLogin(ctx, tenantCode)
	}
	if rec.TenantStatus != "active" || rec.MembershipStatus != "active" ||
		bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)) != nil {
		return security.TokenPair{}, s.rejectLogin(ctx, tenantCode)
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
		return security.TokenPair{}, shared.Unauthorized()
	}
	now := time.Now().UTC()
	oldHash := security.HashRefresh(raw)
	identity, err := s.repo.RefreshIdentity(ctx, oldHash, now)
	if err != nil {
		return security.TokenPair{}, shared.Unauthorized()
	}
	pair, newHash, err := s.tokens.Issue(identity.TenantID, identity.UserID, now)
	if err != nil {
		return security.TokenPair{}, err
	}
	if _, err := s.repo.RotateRefresh(ctx, oldHash, newHash, now, pair.RefreshExpiresAt); err != nil {
		return security.TokenPair{}, shared.Unauthorized()
	}
	return pair, nil
}

func (s *Service) Logout(ctx context.Context, raw string) error {
	if len(raw) < 40 || len(raw) > 128 {
		return shared.Unauthorized()
	}
	return s.repo.RevokeRefresh(ctx, security.HashRefresh(raw), time.Now().UTC())
}

func (s *Service) Authenticate(token string) (shared.Identity, error) {
	claims, err := s.tokens.Parse(token)
	if err != nil {
		return shared.Identity{}, shared.Unauthorized()
	}
	return shared.Identity{TenantID: claims.TenantID, UserID: claims.UserID}, nil
}

func (s *Service) rejectLogin(ctx context.Context, tenantCode string) error {
	if err := s.repo.RecordFailedLogin(ctx, tenantCode); err != nil {
		return err
	}
	return shared.Unauthorized()
}
