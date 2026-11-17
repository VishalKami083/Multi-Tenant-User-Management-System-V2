package repository

import (
	"github.com/jackc/pgx/v5/pgxpool"
	accessrepo "github.com/vishalKami083/multitenant-usermgmt/internal/repository/access"
	auditrepo "github.com/vishalKami083/multitenant-usermgmt/internal/repository/audit"
	authrepo "github.com/vishalKami083/multitenant-usermgmt/internal/repository/auth"
	membershiprepo "github.com/vishalKami083/multitenant-usermgmt/internal/repository/membership"
	"github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	tenantrepo "github.com/vishalKami083/multitenant-usermgmt/internal/repository/tenant"
	userrepo "github.com/vishalKami083/multitenant-usermgmt/internal/repository/user"
)

var (
	ErrNotFound = shared.ErrNotFound
	ErrConflict = shared.ErrConflict
	ErrInvalid  = shared.ErrInvalid
)

type Repository struct {
	*tenantrepo.TenantRepository
	*userrepo.UserRepository
	*authrepo.AuthRepository
	*membershiprepo.MembershipRepository
	*accessrepo.AccessRepository
	*auditrepo.AuditRepository
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{
		TenantRepository:     tenantrepo.New(pool),
		UserRepository:       userrepo.New(pool),
		AuthRepository:       authrepo.New(pool),
		MembershipRepository: membershiprepo.New(pool),
		AccessRepository:     accessrepo.New(pool),
		AuditRepository:      auditrepo.New(pool),
	}
}
