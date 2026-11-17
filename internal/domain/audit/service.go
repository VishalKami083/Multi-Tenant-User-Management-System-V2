package audit

import (
	"context"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type Repository interface {
	AuditLogs(context.Context, string, int, int) ([]repoData.AuditEntry, error)
}

type Service struct{ repo Repository }

func New(repo Repository) *Service { return &Service{repo: repo} }

func (s *Service) List(ctx context.Context, identity shared.Identity, limit, offset int) ([]repoData.AuditEntry, error) {
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, shared.Invalid("limit must be 1-100 and offset must be non-negative")
	}
	return s.repo.AuditLogs(ctx, identity.TenantID, limit, offset)
}
