package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpapi/access"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpapi/audit"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpapi/auth"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpapi/membership"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpapi/tenant"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpapi/user"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpx"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type application interface {
	CreateTenant(context.Context, service.TenantInput) (repoData.Tenant, repoData.User, error)
	GetTenant(context.Context, service.Identity) (repoData.Tenant, error)
	UpdateTenant(context.Context, service.Identity, service.TenantUpdate) (repoData.Tenant, error)
	Login(context.Context, string, string, string) (security.TokenPair, error)
	Refresh(context.Context, string) (security.TokenPair, error)
	Logout(context.Context, string) error
	Authenticate(string) (service.Identity, error)
	RequirePermission(context.Context, service.Identity, string) error
	ListUsers(context.Context, service.Identity, string, int, int) (service.UserPage, error)
	GetUser(context.Context, service.Identity, string) (repoData.User, error)
	CreateUser(context.Context, service.Identity, service.UserInput) (repoData.User, error)
	UpdateUser(context.Context, service.Identity, string, string) (repoData.User, error)
	DeleteUser(context.Context, service.Identity, string) error
	AddMembership(context.Context, service.Identity, string) error
	UpdateMembership(context.Context, service.Identity, string, service.MembershipUpdate) error
	ListRoles(context.Context, service.Identity) ([]repoData.Role, error)
	ListPermissions(context.Context) ([]repoData.Permission, error)
	CreateRole(context.Context, service.Identity, service.RoleInput) (repoData.Role, error)
	AssignRole(context.Context, service.Identity, string, string) error
	RemoveRole(context.Context, service.Identity, string, string) error
	SetRolePermissions(context.Context, service.Identity, string, []string) error
	AuditLogs(context.Context, service.Identity, int, int) ([]repoData.AuditEntry, error)
}

type API struct {
	app    application
	logger *slog.Logger
}

func New(app application, logger *slog.Logger) http.Handler {
	a := &API{app: app, logger: logger}
	tenants := tenant.New(app, logger)
	authHandlers := auth.New(app, logger)
	users := user.New(app, logger)
	memberships := membership.New(app, logger)
	accessHandlers := access.New(app, logger)
	audits := audit.New(app, logger)

	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer)
	r.Use(a.accessLog)
	r.Get("/healthz", a.health)
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/tenants", tenants.Create)
		r.Post("/auth/login", authHandlers.Login)
		r.Post("/auth/refresh", authHandlers.Refresh)
		r.Post("/auth/logout", authHandlers.Logout)
		r.Group(func(r chi.Router) {
			r.Use(a.authenticate)
			r.With(a.permission("tenant:read")).Get("/tenant", tenants.Get)
			r.With(a.permission("tenant:update")).Patch("/tenant", tenants.Update)
			r.With(a.permission("user:create")).Post("/users", users.Create)
			r.With(a.permission("user:read")).Get("/users", users.List)
			r.With(a.permission("user:read")).Get("/users/{userID}", users.Get)
			r.With(a.permission("user:update")).Patch("/users/{userID}", users.Update)
			r.With(a.permission("user:delete")).Delete("/users/{userID}", users.Delete)
			r.With(a.permission("membership:create")).Post("/memberships", memberships.Add)
			r.With(a.permission("membership:update")).Patch("/memberships/{userID}", memberships.Update)
			r.With(a.permission("role:read")).Get("/roles", accessHandlers.ListRoles)
			r.With(a.permission("role:read")).Get("/permissions", accessHandlers.ListPermissions)
			r.With(a.permission("role:create")).Post("/roles", accessHandlers.CreateRole)
			r.With(a.permission("role:assign")).Post("/users/{userID}/roles", accessHandlers.AssignRole)
			r.With(a.permission("role:assign")).Delete("/users/{userID}/roles/{roleID}", accessHandlers.RemoveRole)
			r.With(a.permission("role:update")).Put("/roles/{roleID}/permissions", accessHandlers.SetRolePermissions)
			r.With(a.permission("audit:read")).Get("/audit-logs", audits.List)
		})
	})
	return r
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.Fields(r.Header.Get("Authorization"))
		if len(header) != 2 || !strings.EqualFold(header[0], "Bearer") {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "bearer access token required")
			return
		}
		identity, err := a.app.Authenticate(header[1])
		if err != nil {
			a.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(httpx.WithIdentity(r.Context(), identity)))
	})
}

func (a *API) permission(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.app.RequirePermission(r.Context(), currentIdentity(r), name); err != nil {
				a.fail(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func currentIdentity(r *http.Request) service.Identity {
	return httpx.IdentityFromContext(r.Context())
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	httpx.Fail(w, r, a.logger, err)
}

func (a *API) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		a.logger.InfoContext(r.Context(), "http request", "request_id", middleware.GetReqID(r.Context()),
			"method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
	})
}
