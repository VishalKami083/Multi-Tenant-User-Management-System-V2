package membership

import (
	"context"
	"strings"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
)

type Repository interface {
	AddMembership(context.Context, string, string, string) error
	UpdateMembershipStatus(context.Context, string, string, string, string) error
}

type Service struct{ repo Repository }

type Update struct {
	Status string `json:"status"`
}

func New(repo Repository) *Service { return &Service{repo: repo} }

func (s *Service) Add(ctx context.Context, identity shared.Identity, userID string) error {
	return shared.Translate(s.repo.AddMembership(ctx, identity.TenantID, identity.UserID, userID))
}

func (s *Service) Update(ctx context.Context, identity shared.Identity, userID string, in Update) error {
	status := strings.ToLower(strings.TrimSpace(in.Status))
	if status != "active" && status != "suspended" {
		return shared.Invalid("status must be active or suspended")
	}
	if status == "suspended" && userID == identity.UserID {
		return shared.Invalid("you cannot suspend your own membership")
	}
	return shared.Translate(s.repo.UpdateMembershipStatus(ctx, identity.TenantID, identity.UserID, userID, status))
}
